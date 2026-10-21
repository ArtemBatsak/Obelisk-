#include "Web.h"
#include "path/Path.h"
#include <sstream>
#include <set>
#include <cctype>
#include <cstdlib>


using json = nlohmann::json;

#ifndef OBELISK_VERSION
#define OBELISK_VERSION "dev"
#endif

namespace {

bool constant_time_eq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    unsigned char diff = 0;
    for (size_t i = 0; i < a.size(); ++i)
        diff |= (unsigned char)(a[i] ^ b[i]);
    return diff == 0;
}

std::string trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::set<std::string> split_csv(const std::string& s) {
    std::set<std::string> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, ',')) {
        part = trim(part);
        if (!part.empty()) out.insert(part);
    }
    return out;
}

std::string body_field(const httplib::Request& req, const char* key, const std::string& def = {}) {
    try {
        auto j = json::parse(req.body);
        if (j.is_object() && j.contains(key) && !j.at(key).is_null())
            return j.at(key).get<std::string>();
    }
    catch (...) {}
    return def;
}

int body_int(const httplib::Request& req, const char* key, int def = 0) {
    try {
        auto j = json::parse(req.body);
        if (j.is_object() && j.contains(key) && j.at(key).is_number_integer())
            return j.at(key).get<int>();
    }
    catch (...) {}
    return def;
}

// Читаем сегмент {user_id} из пути /api/service/users/{user_id}[/action]
std::string path_user_id(const httplib::Request& req) {
    const std::string prefix = "/api/service/users/";
    if (req.path.rfind(prefix, 0) != 0) return {};
    std::string rest = req.path.substr(prefix.size());
    auto pos = rest.find('/');
    if (pos != std::string::npos) rest = rest.substr(0, pos);
    return rest;
}

} // namespace

std::string base64_decode(const std::string& in) {
	BIO* b64 = BIO_new(BIO_f_base64());
	BIO* mem = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
	BIO* chain = BIO_push(b64, mem);
	BIO_set_flags(chain, BIO_FLAGS_BASE64_NO_NL);

	std::vector<char> out(in.size());
	int len = BIO_read(chain, out.data(), static_cast<int>(out.size()));
	BIO_free_all(chain);

	if (len <= 0) return {};
	return std::string(out.data(), len);
}


WebAdmin::~WebAdmin() {
	stop();

}


void WebAdmin::setup_tls_in_memory() {
	const auto cfg = web_wizard->get_config();
	tls_cert_path = cfg.tls_cert_path;
	tls_key_path = cfg.tls_key_path;
}

std::string WebAdmin::detect_external_ip() {
	// 1) Явно заданный внешний IP (env OBELISK_PUBLIC_IP / config) — не ходим в интернет.
	const Config cfg = web_wizard->get_config();
	if (!cfg.public_ip.empty()) {
		return cfg.public_ip;
	}

	// 2) Кэш: определяем один раз, а не на каждый запрос.
	if (!public_ip_cache_.empty()) {
		return public_ip_cache_;
	}

	// 3) Однократное определение. При сбое НЕ отдаём 127.0.0.1 (это ломает лаунчер).
	httplib::SSLClient client("api.ipify.org", 443);
	client.set_connection_timeout(3, 0);
	client.set_read_timeout(3, 0);
	auto res = client.Get("/?format=json");
	if (!res || res->status != 200) {
		spdlog::warn("Failed to detect external IP; set OBELISK_PUBLIC_IP to avoid this");
		return {};
	}

	try {
		auto body = json::parse(res->body);
		public_ip_cache_ = body.value("ip", std::string());
		return public_ip_cache_;
	}
	catch (...) {
		spdlog::warn("Invalid response while detecting external IP");
		return {};
	}
}

void WebAdmin::apply_auth_middleware() {

	svr->set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {
		const std::string path = req.path;
		const Config cfg = web_wizard->get_config();

		// 1) /api/health — без авторизации (обезличенная самопроверка)
		if (path == "/api/health") {
			return httplib::Server::HandlerResponse::Unhandled;
		}

		// 2) /api/service/* — machine-to-machine via X-Service-Key (+ опциональный IP-allowlist)
		if (path.rfind("/api/service/", 0) == 0 || path == "/api/service") {
			const std::string key = req.get_header_value("X-Service-Key");
			const bool key_ok = !cfg.service_api_key.empty() && constant_time_eq(key, cfg.service_api_key);

			bool ip_ok = true;
			if (!cfg.allow_api_peers.empty()) {
				ip_ok = split_csv(cfg.allow_api_peers).count(req.remote_addr) > 0;
			}

			if (key_ok && ip_ok) {
				return httplib::Server::HandlerResponse::Unhandled;
			}
			res.status = 401;
			res.set_content(json({ {"status","error"}, {"message","service auth failed"} }).dump(), "application/json");
			return httplib::Server::HandlerResponse::Handled;
		}

		// 3) остальное — админ Basic
		if (req.has_header("Authorization")) {
			std::string auth = req.get_header_value("Authorization");
			if (auth.size() >= 7 && auth.substr(0, 6) == "Basic ") {
				std::string base64_part = auth.substr(6);
				std::string decoded = base64_decode(base64_part);
				size_t sep = decoded.find(':');
				if (sep != std::string::npos) {
					std::string user = decoded.substr(0, sep);
					std::string pass = decoded.substr(sep + 1);
					if (this->web_wizard->verify_password(user, pass)) {
						return httplib::Server::HandlerResponse::Unhandled;
					}
				}
			}
		}

		res.status = 401;
		res.set_header("WWW-Authenticate", "Basic realm=\"Admin Panel\"");
		res.set_content("Access denied", "text/plain");
		return httplib::Server::HandlerResponse::Handled;
		});
}

void WebAdmin::start() {
	if (m_running) return;

	setup_tls_in_memory();

	svr = std::make_unique<httplib::SSLServer>(tls_cert_path.c_str(), tls_key_path.c_str());

	if (!svr->is_valid()) {
		spdlog::error("WebAdmin: SSL Server is NOT valid (cert: {}, key: {})", tls_cert_path, tls_key_path);
		return;
	}

	spdlog::info("WebAdmin: SSL Server initialized successfully from certificate files.");
	apply_auth_middleware();

	// ---Statick---

	svr->Get("/", [this](const httplib::Request&, httplib::Response& res) {
		res.set_content(INDEX_HTML_PART_1 + INDEX_JS_PART_2, "text/html; charset=utf-8");
		});

	// --- API: get all servers ---
	svr->Get("/api/servers", [this](const httplib::Request&, httplib::Response& res) {

		auto servers = web_data_servers->get_servers();

		nlohmann::json j = nlohmann::json::array();

		for (const auto& s : servers)
		{
			bool online = web_server_manager->server_online(s.id);
			int active_pairs = web_server_manager->get_active_pairs(s.id);
			auto last_seen = -1;
			uint64_t speed_in = 0;
			uint64_t speed_out = 0;
			uint64_t total_traffic = s.total_traffic;
			if (online) {
				last_seen = web_server_manager->get_ping(s.id);
				speed_in = web_server_manager->get_total_speed_in(s.id);
				speed_out = web_server_manager->get_total_speed_out(s.id);
				total_traffic = web_data_servers->get_total_traffic_by_id(s.id);
			}



			j.push_back({
				{"id", s.id},
				{"client_port", s.client_port},
				{"comment", s.comment},
				{"last_seen", last_seen},
				{"active_pairs", active_pairs},
				{"online", online},
				{"speed_in", speed_in},
				{"speed_out", speed_out},
				{"total_traffic", total_traffic}
				});
		}

		res.set_content(j.dump(), "application/json");
		});

	// --- API: Logs ---
	svr->Get("/api/logs", [](const httplib::Request&, httplib::Response& res) {
		std::string log_path = Path::LogFile();
		std::string content = "";

		if (std::filesystem::exists(log_path)) {
			std::ifstream file(log_path, std::ios::binary | std::ios::ate);
			if (file.is_open()) {
				auto size = file.tellg();
				auto to_read = std::min<std::streamoff>(size, 4096);
				file.seekg(size - to_read);

				std::vector<char> buffer(to_read);
				file.read(buffer.data(), to_read);
				content = std::string(buffer.data(), buffer.size());

				auto first_newline = content.find('\n');
				if (first_newline != std::string::npos && size > 4096) {
					content = content.substr(first_newline + 1);
				}
			}
		}
		else {
			content = "[INFO] We don`t have a logs file";
		}
		res.set_content(json({ {"logs", content} }).dump(), "application/json");
		});

	// --- API: delete server ---
	svr->Post("/api/server/delete", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_server_manager->delete_server(j.at("id").get<uint32_t>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	// --- API: change comment ---
	svr->Post("/api/server/change_comment", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_data_servers->updateServerComment(j.at("id").get<uint32_t>(), j.at("comment").get<std::string>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	// --- API: add server ---
	svr->Post("/api/server/add", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			const auto external_ip = detect_external_ip();
			const int control_port = web_server_manager->get_control_port();
			const auto trusted_server_certificate = web_server_manager->get_tls_certificate_pem();
			bool success = web_data_servers->add_id(j.at("comment").get<std::string>(), control_port, external_ip, trusted_server_certificate);
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	svr->Get("/api/server/config", [this](const httplib::Request& req, httplib::Response& res) {
		if (!req.has_param("id")) {
			res.status = 400;
			res.set_content(json({ {"status", "error"}, {"message", "missing id"} }).dump(), "application/json");
			return;
		}

		try {
			const uint32_t id = static_cast<uint32_t>(std::stoul(req.get_param_value("id")));
			std::string content;
			if (!web_data_servers->read_server_config_file(id, content)) {
				res.status = 404;
				res.set_content(json({ {"status", "error"}, {"message", "config not found"} }).dump(), "application/json");
				return;
			}

			res.set_header("Content-Disposition", "attachment; filename=\"server_" + std::to_string(id) + ".json\"");
			res.set_content(content, "application/json");
		}
		catch (...) {
			res.status = 400;
			res.set_content(json({ {"status", "error"}, {"message", "bad id"} }).dump(), "application/json");
		}
		});

	// --- API: stop server ---
	// We can stop server, but we can`t start it again
	svr->Post("/api/server/stop", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_server_manager->shutdown_id(j.at("id").get<uint32_t>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	svr->Get("/api/ports/list", [this](const httplib::Request& req, httplib::Response& res) {
		res.set_content(web_data_servers->get_port_pool(), "application/json");
		});

	svr->Post("/api/ports/delete", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			int first = j.at("first").get<int>();
			int second = j.contains("second") ? j.at("second").get<int>() : 0;

			bool success = web_data_servers->delete_port(first, second);
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	svr->Post("/api/ports/add", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = nlohmann::json::parse(req.body);


			int first = j.at("first").get<int>();
			int second = j.at("second").get<int>();


			bool success = web_data_servers->add_ports(first, second);

			res.set_content(nlohmann::json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (const std::exception& e) {
			spdlog::error("API Error (add_ports): {}", e.what());
			res.status = 400;
			res.set_content(nlohmann::json({ {"status", "error"}, {"message", "Invalid JSON or parameters"} }).dump(), "application/json");
		}
		catch (...) {
			res.status = 500;
		}
		});

	// --- Metrics ---
	svr->Get("/metrics", [this](const httplib::Request&, httplib::Response& res) {
		std::ostringstream out;
		auto servers = web_data_servers->get_servers();
		out << "# HELP obelisk_servers_total Total registered servers\n";
		out << "# TYPE obelisk_servers_total gauge\n";
		out << "obelisk_servers_total " << servers.size() << "\n\n";
		for (const auto& s : servers) {
			bool online = web_server_manager->server_online(s.id);
			out << "obelisk_server_info{id=\"" << s.id << "\",comment=\""
				<< s.comment << "\"} " << (online ? 1 : 0) << "\n";
			if (online) {
				out << "obelisk_active_pairs{id=\"" << s.id << "\"} "
					<< web_server_manager->get_active_pairs(s.id) << "\n";
				out << "obelisk_ping_ms{id=\"" << s.id << "\"} "
					<< web_server_manager->get_ping(s.id) << "\n";
				out << "obelisk_traffic_total{id=\"" << s.id << "\"} "
					<< web_data_servers->get_total_traffic_by_id(s.id) << "\n";
				out << "obelisk_speed_in_bytes{id=\"" << s.id << "\"} "
					<< web_server_manager->get_total_speed_in(s.id) << "\n";
				out << "obelisk_speed_out_bytes{id=\"" << s.id << "\"} "
					<< web_server_manager->get_total_speed_out(s.id) << "\n";
			}
			out << "\n";
		}
		res.set_content(out.str(), "text/plain; charset=utf-8");
		});

	// --- Aggregate (health / monitor) helpгers ---
	auto aggregate = [this]() {
		json a;
		const auto servers = web_data_servers->get_servers();
		int online = 0;
		uint64_t active_pairs_total = 0;
		uint64_t speed_in = 0, speed_out = 0, total_traffic = 0;
		for (const auto& s : servers) {
			if (web_server_manager->server_online(s.id)) {
				++online;
				active_pairs_total += web_server_manager->get_active_pairs(s.id);
				speed_in += web_server_manager->get_total_speed_in(s.id);
				speed_out += web_server_manager->get_total_speed_out(s.id);
			}
			total_traffic += web_data_servers->get_total_traffic_by_id(s.id);
		}
		int free_ports = 0;
		try {
			auto pool = json::parse(web_data_servers->get_port_pool());
			free_ports = pool.value("count", 0);
		} catch (...) {}
		std::set<int> unique_ports;
		for (const auto& s : servers) {
			if (s.client_port > 0) unique_ports.insert(s.client_port);
		}
		a["node_id"] = web_wizard->get_config().node_id;
		a["online_servers"] = online;
		a["users"] = static_cast<int>(servers.size());
		a["unique_ports"] = static_cast<int>(unique_ports.size());
		a["active_pairs"] = static_cast<uint64_t>(active_pairs_total);
		a["speed_in"] = speed_in;
		a["speed_out"] = speed_out;
		a["total_traffic"] = total_traffic;
		a["free_ports"] = free_ports;
		a["uptime_sec"] = static_cast<uint64_t>(
			std::chrono::duration_cast<std::chrono::seconds>(
				std::chrono::steady_clock::now() - start_time_).count());
		return a;
	};

	// --- GET /api/health (no auth) ---
	svr->Get("/api/health", [this, aggregate](const httplib::Request&, httplib::Response& res) {
		json j = aggregate();
		j["status"] = "ok";
		j["version"] = OBELISK_VERSION;
		res.set_content(j.dump(), "application/json");
		});

	// --- GET /api/monitor (метрики для вкладки мониторинг) ---
	svr->Get("/api/monitor", [this, aggregate](const httplib::Request&, httplib::Response& res) {
		res.set_content(aggregate().dump(), "application/json");
		});

	// --- POST /api/admin/restart (graceful exit → supervisor перезапустит) ---
	svr->Post("/api/admin/restart", [this](const httplib::Request&, httplib::Response& res) {
		res.set_content(json({ {"status","restarting"} }).dump(), "application/json");
		std::thread([this]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(300));
			std::exit(0);
		}).detach();
		});

	// --- 5 service endpoints (X-Service-Key) ---
	svr->Get("/api/service/snapshot", [this](const httplib::Request&, httplib::Response& res) {
		auto servers = web_data_servers->get_servers();
		int online = 0;
		uint64_t pairs = 0;
		uint64_t speed_in = 0;
		uint64_t speed_out = 0;
		uint64_t total = 0;
		std::set<int> unique_ports;
		json hosts = json::array();
		for (const auto& s : servers) {
			const bool on = web_server_manager->server_online(s.id);
			const int active = on ? static_cast<int>(web_server_manager->get_active_pairs(s.id)) : 0;
			if (s.client_port > 0) unique_ports.insert(s.client_port);
			if (on) {
				++online;
				pairs += static_cast<uint64_t>(active);
				speed_in += web_server_manager->get_total_speed_in(s.id);
				speed_out += web_server_manager->get_total_speed_out(s.id);
			}
			total += web_data_servers->get_total_traffic_by_id(s.id);
			hosts.push_back({
				{"id", s.id},
				{"user_id", s.user_id},
				{"online", on},
				{"active_pairs", active},
			});
		}
		int free_ports = 0;
		try {
			auto pool = json::parse(web_data_servers->get_port_pool());
			free_ports = pool.value("count", 0);
		} catch (...) {}
		json j = {
			{"status", "ok"},
			{"online_servers", online},
			{"active_pairs", pairs},
			{"speed_in", speed_in},
			{"speed_out", speed_out},
			{"total_traffic", total},
			{"free_ports", free_ports},
			{"users", static_cast<int>(servers.size())},
			{"unique_ports", static_cast<int>(unique_ports.size())},
			{"hosts", hosts},
		};
		res.set_content(j.dump(), "application/json");
		});

	svr->Post("/api/service/users", [this](const httplib::Request& req, httplib::Response& res) {
		const std::string user_id = body_field(req, "user_id");
		const std::string comment = body_field(req, "comment");
		const int requested_port = body_int(req, "requested_port", 0);
		if (user_id.empty()) {
			res.status = 400;
			res.set_content(json({ {"status","error"}, {"message","user_id is required"} }).dump(), "application/json");
			return;
		}
		const Config cfg = web_wizard->get_config();
		const int control_port = web_server_manager->get_control_port();
		const std::string external_ip = detect_external_ip();
		const std::string trusted = web_server_manager->get_tls_certificate_pem();
		Server_struct entry;
		bool exists = false;
		if (!web_data_servers->create_user(user_id, comment, requested_port, control_port,
			external_ip, trusted, cfg.max_sessions, entry, exists)) {
			res.status = 503;
			res.set_content(json({ {"status","error"}, {"message","cannot provision (no free ports or limit reached)"} }).dump(), "application/json");
			return;
		}
		std::string config_raw;
		json config_obj = json::object();
		if (web_data_servers->read_server_config_file(entry.id, config_raw)) {
			try { config_obj = json::parse(config_raw); } catch (...) {}
		}
		json j = {
			{"status","ok"},
			{"id", entry.id},
			{"client_port", entry.client_port},
			{"public_ip", external_ip},
			{"enabled", entry.enabled},
			{"exists", exists},
			{"config", config_obj}
		};
		res.set_content(j.dump(), "application/json");
		});

	svr->Get(R"(/api/service/users/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
		const std::string user_id = path_user_id(req);
		Server_struct s;
		if (user_id.empty() || !web_data_servers->get_by_user_id(user_id, s)) {
			res.status = 404;
			res.set_content(json({ {"status","error"}, {"message","user not found"} }).dump(), "application/json");
			return;
		}
		json j = {
			{"id", s.id},
			{"client_port", s.client_port},
			{"public_ip", detect_external_ip()},
			{"enabled", s.enabled},
			{"online", web_server_manager->server_online(s.id)},
			{"active_pairs", web_server_manager->get_active_pairs(s.id)},
			{"total_traffic", web_data_servers->get_total_traffic_by_id(s.id)}
		};
		res.set_content(j.dump(), "application/json");
		});

	svr->Post(R"(/api/service/users/([^/]+)/enable)", [this](const httplib::Request& req, httplib::Response& res) {
		const std::string user_id = path_user_id(req);
		Server_struct s;
		if (user_id.empty() || !web_data_servers->get_by_user_id(user_id, s)) {
			res.status = 404;
			res.set_content(json({ {"status","error"}, {"message","user not found"} }).dump(), "application/json");
			return;
		}
		web_data_servers->set_enabled(s.id, true);
		std::string config_raw;
		json config_obj = json::object();
		if (web_data_servers->read_server_config_file(s.id, config_raw)) {
			try { config_obj = json::parse(config_raw); } catch (...) {}
		}
		json j = {
			{"status","ok"},
			{"enabled", true},
			{"public_ip", detect_external_ip()},
			{"client_port", s.client_port},
			{"config", config_obj}
		};
		res.set_content(j.dump(), "application/json");
		});

	svr->Post(R"(/api/service/users/([^/]+)/suspend)", [this](const httplib::Request& req, httplib::Response& res) {
		const std::string user_id = path_user_id(req);
		Server_struct s;
		if (user_id.empty() || !web_data_servers->get_by_user_id(user_id, s)) {
			res.status = 404;
			res.set_content(json({ {"status","error"}, {"message","user not found"} }).dump(), "application/json");
			return;
		}
		web_data_servers->set_enabled(s.id, false);
		web_server_manager->shutdown_id(s.id);
		res.set_content(json({ {"status","ok"}, {"enabled", false} }).dump(), "application/json");
		});

	svr->Delete(R"(/api/service/users/([^/]+))", [this](const httplib::Request& req, httplib::Response& res) {
		const std::string user_id = path_user_id(req);
		Server_struct s;
		if (user_id.empty() || !web_data_servers->get_by_user_id(user_id, s)) {
			res.status = 404;
			res.set_content(json({ {"status","error"}, {"message","user not found"} }).dump(), "application/json");
			return;
		}
		bool ok = web_server_manager->delete_server(s.id);
		res.set_content(json({ {"status", ok ? "ok" : "error"}, {"deleted", ok} }).dump(), "application/json");
		});

	// --- Aggregate stats в одном запросе (X-Service-Key) ---
	// Онлайн, скорость, трафик, свободные порты, аптайм — одним вызовом для бэкенда.
	svr->Get("/api/service/stats", [this, aggregate](const httplib::Request&, httplib::Response& res) {
		json j = aggregate();
		j["status"] = "ok";
		res.set_content(j.dump(), "application/json");
		});

	spdlog::info("Admin panel started at https://{}:{}", web_wizard->get_config().web_bind, port_);
	m_running = true;
	svr->listen(web_wizard->get_config().web_bind, port_);
}

void WebAdmin::stop() {
	if (m_running) {
		m_running = false;
		svr->stop();
		spdlog::info("Admin panel stopped");
	}

}
