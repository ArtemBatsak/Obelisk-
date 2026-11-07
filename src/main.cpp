#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <array>
#include <filesystem>
#include <coroutine>
#include <cstdio>
#define ASIO_HAS_CO_AWAIT
#define ASIO_HAS_STD_COROUTINE 
#include <asio.hpp>
#ifdef _WIN32
#include <winsock2.h> 
#else
#include <arpa/inet.h>
#include <csignal>
#endif
#include "manager/Data.h"
#include "server/Server_class.h"
#include "manager/Server_manager.h"
#include "logger/Logger.h"
#include "web/Web.h"
#include "manager/Setup_wizard.h"
#include "path/Path.h"

#ifndef OBELISK_VERSION
#define OBELISK_VERSION "dev"
#endif

#ifndef GIT_HASH
#define GIT_HASH "unknown"
#endif

auto running = std::make_shared<std::atomic<bool>>(true);

int CONTROL_PORT;
int DATA_PORT;
int WEB_PORT;

std::string CONFIG_PATH = Path::ConfigFile();
std::string TLS_CERT_PATH = Path::CertFile();
std::string TLS_KEY_PATH = Path::KeyFile();

int main(int argc, char* argv[])
{
    Path::EnsureDirs();
    Path::EnsureDataFiles();
    Path::EnsureLogFiles();
    try
    {
        init_logging();
        spdlog::info("Obelisk {} ({})", OBELISK_VERSION, GIT_HASH);
        spdlog::info("Log path: {}", Path::LogFile());
		// --- Configuration ---
		auto wizard = std::make_shared<ConfigManager>();

		// --- CLI: --version / --check / --dump-config ---
		for (int i = 1; i < argc; ++i) {
			const std::string a = argv[i];
			if (a == "--version") {
				std::printf("Obelisk %s (%s)\n", OBELISK_VERSION, GIT_HASH);
				return 0;
			}
			if (a == "--check") {
				const bool ok = wizard->check_config();
				if (!ok) {
					std::printf("Config check FAILED\n");
					return 1;
				}
				const auto c = wizard->get_config();
				std::printf("Config OK: node=%s control=%d data=%d web=%d pool=%d-%d max_sessions=%d\n",
					c.node_id.c_str(), c.control_port, c.data_port, c.web_port,
					c.port_pool_start, c.port_pool_end, c.max_sessions);
				return 0;
			}
			if (a == "--dump-config") {
				wizard->check_config();
				const auto c = wizard->get_config();
				nlohmann::json j;
				j["node_id"] = c.node_id;
				j["control_port"] = c.control_port;
				j["data_port"] = c.data_port;
				j["web_port"] = c.web_port;
				j["web_bind"] = c.web_bind;
				j["max_pending_clients"] = c.max_pending_clients;
				j["max_sessions"] = c.max_sessions;
				j["port_pool_start"] = c.port_pool_start;
				j["port_pool_end"] = c.port_pool_end;
				j["data_pool_max"] = c.data_pool_max;
				j["allow_api_peers"] = c.allow_api_peers;
				j["admin_username"] = c.admin_username;
				j["service_api_key_set"] = !c.service_api_key.empty();
				std::printf("%s\n", j.dump(4).c_str());
				return 0;
			}
		}

		if (!wizard->check_config())
        {
            spdlog::info("No config file found. Starting setup wizard...");
            wizard->set_up();
        }
		auto config = wizard->get_config();
		CONTROL_PORT = config.control_port;
		DATA_PORT = config.data_port;
		WEB_PORT = config.web_port;
		// --- Data ---
        auto data_servers = std::make_shared<DataServers>();
		// Автозаполнение пула портов из env/конфига
		if (config.port_pool_start > 0 && config.port_pool_end >= config.port_pool_start) {
			data_servers->add_ports(config.port_pool_start, config.port_pool_end);
			spdlog::info("Port pool ensured: {}-{}", config.port_pool_start, config.port_pool_end);
		}
		// --- Server Manager ---
        asio::io_context io;
        auto server_manager = std::make_shared<ServerManager>(
            running,
            CONTROL_PORT,
            DATA_PORT,
            data_servers,
            TLS_CERT_PATH,
            TLS_KEY_PATH,
            io.get_executor(),
            config.max_pending_clients,
            config.data_pool_max
        );
		server_manager->start();

        // --- Web Admin ---
        WebAdmin admin(data_servers, server_manager, wizard, WEB_PORT);

        std::thread web_thread([&admin]()
            {
                admin.start(); 
            });

        // --- Signal handling ---
        asio::signal_set signals(io);

#ifdef _WIN32
        signals.add(SIGINT);
#else
        signals.add(SIGINT);
        signals.add(SIGTERM);
#endif

        signals.async_wait([&](const asio::error_code&, int)
            {
                spdlog::info("Shutdown signal received...");

                *running = false;

                admin.stop();                    
                server_manager->shutdown_all();  

                // Даём strand'ам серверов время провести cleanup (закрыть сокеты/пары)
                // до остановки io_context. Иначе io.stop() отменит поставленные
                // shutdown() и сокеты не закроются (см. shutdown_timer_ в ServerManager).
                auto stop_timer = std::make_shared<asio::steady_timer>(io);
                stop_timer->expires_after(std::chrono::milliseconds(3000));
                stop_timer->async_wait([&io, stop_timer](const asio::error_code& ec)
                    {
                        if (ec == asio::error::operation_aborted) return;
                        spdlog::info("Shutdown grace window elapsed, stopping io_context");
                        io.stop();
                    });
            });

        // --- Thread pool ---
        unsigned int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0)
            num_threads = 1;
        
        std::vector<std::thread> threads;
        threads.reserve(num_threads);

        for (unsigned int i = 0; i < num_threads; ++i)
        {
            threads.emplace_back([&io]()
                {
                    io.run();
                });
        }

        // --- Wait for workers ---
        for (auto& t : threads)
            t.join();

        // --- Wait for Web thread ---
        if (web_thread.joinable())
            web_thread.join();

        spdlog::info("Obelisk has stopped");
    }
    catch (const std::exception& e)
    {
        spdlog::error("Fatal exception: {}", e.what());
        spdlog::error("If this was a bind error, ensure control/data/web ports are free.");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}