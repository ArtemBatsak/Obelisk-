#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <array>
#include <coroutine>
#define ASIO_HAS_CO_AWAIT
#define ASIO_HAS_STD_COROUTINE 
#include <asio.hpp>
#ifdef _WIN32
#include <winsock2.h> // htonl/ntohl
#else
#include <arpa/inet.h>
#include <csignal>
#endif
#include "manager/Data.h"
#include "server/Server_class.h"
#include "manager/Server_manager.h"
#include "logger/logger.h"
#include "web/web.h"
#include "manager/Setup_Wizard.h"

auto running = std::make_shared<std::atomic<bool>>(true);

int CONTROL_PORT;
int DATA_PORT;
int WEB_PORT;




int main()
{
    try
    {
        init_logging();
        spdlog::info("Obelisk started");
		// --- Configuration ---
		auto wizard = std::make_shared<ConfigManager>();
		if (!wizard->check_config())
        {
            spdlog::info("No config file found. Starting setup wizard...");
            wizard->set_up();
        }
		auto config = wizard->get_config();
		CONTROL_PORT = config.control_port;
		DATA_PORT = config.data_port;
		WEB_PORT = config.web_port;
		// --- Server Manager ---
        asio::io_context io;
        auto data_servers = std::make_shared<DataServers>();
        auto server_manager = std::make_shared<ServerManager>(
            running,
            CONTROL_PORT,
            DATA_PORT,
            data_servers,
            io.get_executor()
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
                io.stop();                       
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
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}