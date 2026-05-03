#include "Web.h"


using json = nlohmann::json;

std::string base64_decode(const std::string& in) {
	static const std::string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	std::vector<int> T(256, -1);
	for (int i = 0; i < 64; i++) T[table[i]] = i;

	int val = 0, valb = -8;
	std::string out;
	for (unsigned char c : in) {
		if (T[c] == -1) break;
		val = (val << 6) + T[c];
		valb += 6;
		if (valb >= 0) {
			out.push_back(char((val >> valb) & 0xFF));
			valb -= 8;
		}
	}
	return out;
}


WebAdmin::~WebAdmin() {
	stop();

}


void WebAdmin::setup_tls_in_memory() {
	const auto cfg = web_wizard->get_config();
	tls_cert_path = cfg.tls_cert_path;
	tls_key_path = cfg.tls_key_path;
}

std::string WebAdmin::detect_external_ip() const {
	httplib::SSLClient client("api.ipify.org", 443);
	client.set_connection_timeout(3, 0);
	client.set_read_timeout(3, 0);
	auto res = client.Get("/?format=json");
	if (!res || res->status != 200) {
		spdlog::warn("Failed to detect external IP, fallback to 127.0.0.1");
		return "127.0.0.1";
	}

	try {
		auto body = json::parse(res->body);
		return body.value("ip", std::string("127.0.0.1"));
	}
	catch (...) {
		spdlog::warn("Invalid response while detecting external IP");
		return "127.0.0.1";
	}
}

void WebAdmin::apply_auth_middleware() {


	svr->set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res) {

		// Check for Authorization header
		if (req.has_header("Authorization")) {
			std::string auth = req.get_header_value("Authorization"); // "Basic YWRtaW46MTIz"

			// Check if it starts with "Basic "
			std::string base64_part = auth.substr(6);


			std::string decoded = base64_decode(base64_part);

			// The decoded string should be in the format "username:password"
			size_t sep = decoded.find(':');
			if (sep != std::string::npos) {
				std::string user = decoded.substr(0, sep);
				std::string pass = decoded.substr(sep + 1);
				// Verify credentials using ConfigManager
				if (this->web_wizard->verify_password(user, pass)) {

					return httplib::Server::HandlerResponse::Unhandled;
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
		std::string log_path = "logs/obelisk.log";
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
			bool success = web_server_manager->delete_server(j.at("id").get<uint32_t>()); res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
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

	spdlog::info("Admin panel started at https://localhost:{}", port_);
	m_running = true;
	svr->listen("0.0.0.0", port_);
}

void WebAdmin::stop() {
	if (m_running) {
		m_running = false;
		svr->stop();
		spdlog::info("Admin panel stopped");
	}

}
