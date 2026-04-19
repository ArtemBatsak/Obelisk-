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
	auto pem = generate_self_signed_cert_pem();
	this->mem_key = pem.first;
	this->mem_cert = pem.second;
	if (mem_key.empty() || mem_cert.empty()) {

		spdlog::error("WebAdmin: Failed to generate in-memory TLS cert/key!");
		return;
	}

	// Check the beginning of the PEM strings to ensure they look correct (for debugging)
	//spdlog::info("Key start: {}", mem_key.substr(0, 25));
	//spdlog::info("Cert start: {}", mem_cert.substr(0, 25));

	if (mem_key.find("BEGIN RSA PRIVATE KEY") == std::string::npos &&
		mem_key.find("BEGIN PRIVATE KEY") == std::string::npos) {
		spdlog::error("WebAdmin: Generated key PEM does not look correct!");
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
				if (this->web_wizard->verify_password(user,pass)) {
					
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
	// Somthing went wrong with in-memory cert generation
	// We can`t start server without certs, so we will try to write them to temp files and load from there
	// After loading, we can delete these files, because SSLServer should have loaded the certs into memory
	std::string cert_path = "web_admin.crt";
	std::string key_path = "web_admin.key";

	try {
		std::ofstream cert_file(cert_path, std::ios::binary);
		cert_file << mem_cert;
		cert_file.close();

		std::ofstream key_file(key_path, std::ios::binary);
		key_file << mem_key;
		key_file.close();
	}
	catch (const std::exception& e) {
		spdlog::error("WebAdmin: Failed to write temp SSL files: {}", e.what());
		return;
	}

	svr = std::make_unique<httplib::SSLServer>(cert_path.c_str(), key_path.c_str());

	if (!svr->is_valid()) {
		spdlog::error("WebAdmin: SSL Server is NOT valid even from temporary files!");
		std::filesystem::remove(cert_path);
		std::filesystem::remove(key_path);
		return;
	}

	spdlog::info("WebAdmin: SSL Server initialized successfully with in-memory certs!");
	apply_auth_middleware();

	// ---Statick---
	svr->Get("/", [](const httplib::Request&, httplib::Response& res) {
		res.set_content(INDEX_HTML, "text/html; charset=utf-8");
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
			if (online)  last_seen = web_server_manager->get_ping(s.id);
			
		

			j.push_back({
				{"id", s.id},
				{"client_port", s.client_port},
				{"comment", s.comment},
				{"last_seen", last_seen},
				{"active_pairs", active_pairs},
				{"online", online}
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
			bool success = web_data_servers->deleteServerById(j.at("id").get<uint32_t>());
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
			bool success = web_data_servers->add_id(j.at("comment").get<std::string>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
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