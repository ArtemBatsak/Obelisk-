#include "web.h"


using json = nlohmann::json;



WebAdmin::~WebAdmin() {
	stop();
}

void WebAdmin::start() {
	httplib::Server svr;
	m_running = true;

	// ---Statick---
	svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
		res.set_content(INDEX_HTML, "text/html; charset=utf-8");
		});

	// --- API: get all servers ---
	svr.Get("/api/servers", [this](const httplib::Request&, httplib::Response& res) {

		auto servers = web_data_servers->get_servers();

		nlohmann::json j = nlohmann::json::array();

		for (const auto& s : servers)
		{
			bool online = web_server_manager->server_online(s.id);
			int active_pairs = web_server_manager->get_active_pairs(s.id);
			auto last_seen = web_server_manager->get_ping(s.id);

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
	svr.Get("/api/logs", [](const httplib::Request&, httplib::Response& res) {
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
	svr.Post("/api/server/delete", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_data_servers->deleteServerById(j.at("id").get<uint32_t>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	// --- API: change comment ---
	svr.Post("/api/server/change_comment", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_data_servers->updateServerComment(j.at("id").get<uint32_t>(), j.at("comment").get<std::string>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	// --- API: add server ---
	svr.Post("/api/server/add", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_data_servers->add_id(j.at("comment").get<std::string>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	// --- API: stop server ---
	// We can stop server, but we can`t start it again
	svr.Post("/api/server/stop", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = json::parse(req.body);
			bool success = web_server_manager->shutdown_id(j.at("id").get<uint32_t>());
			res.set_content(json({ {"status", success ? "ok" : "error"} }).dump(), "application/json");
		}
		catch (...) { res.status = 400; }
		});

	svr.Post("/api/ports/add", [this](const httplib::Request& req, httplib::Response& res) {
		try {
			auto j = nlohmann::json::parse(req.body);

			
			int first = j.at("first").get<int>();
			int second = j.at("second").get<int>();

			// Вызываем нашу крутую функцию с std::set
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
	std::cout << ">>> Admin panel started at http://localhost:" << port_ << std::endl;
	m_running = true;
	svr.listen("0.0.0.0", port_);
}

void WebAdmin::stop() {
	if (m_running) {
		m_running = false;
		svr_.stop();  
		spdlog::info("Admin panel stopped");
	}
	
}



