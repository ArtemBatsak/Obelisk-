#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <array>
#include <coroutine>
#define ASIO_HAS_CO_AWAIT
#define ASIO_HAS_STD_COROUTINE // <--- Это заставит Asio искать в std::, а не в std::experimental
#include <coroutine>
#include <asio.hpp>
#include <asio/ssl.hpp>
#ifdef _WIN32
#include <winsock2.h> // htonl/ntohl
#else
#include <arpa/inet.h>
#include <csignal>
#endif

#include "tls/tls_session.h"
#include "manager/Data.h"
#include "server/Server_class.h"
#include "logger/logger.h"
#include "web/web.h"

using asio::ip::tcp;
int WEB_PORT = 8000;
std::atomic<bool> running(true);
const int CONTROL_PORT = 44555;

struct Ports {
    uint32_t data_port;
    uint32_t client_port;
};


void start_control_accept(
    asio::ssl::context& ssl_ctx, 
    tcp::acceptor& acceptor, 
    std::shared_ptr<DataServers> data_servers, 
    asio::io_context& io, 
    std::shared_ptr<ServerManager> server_manager);

asio::awaitable<void> async_authorize(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<DataServers> data_servers,
    std::shared_ptr<ServerManager> server_manager
);

int main()
{
    try
    {
        init_logging();
        spdlog::info("Obelisk started");

        asio::io_context io;

        auto data_servers = std::make_shared<DataServers>();
        auto server_manager = std::make_shared<ServerManager>();

        // --- Web Admin ---
        WebAdmin admin(data_servers, server_manager, WEB_PORT);

        std::thread web_thread([&admin]()
            {
                admin.start(); // блокирующий вызов
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

                running = false;

                admin.stop();                    
                server_manager->shutdown_all();  
                io.stop();                       
            });

        // --- TLS context ---
        asio::ssl::context ssl_ctx(asio::ssl::context::tls_server);
        ssl_ctx.set_options(
            asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::no_sslv3
            | asio::ssl::context::single_dh_use
        );

        auto pem = generate_self_signed_cert_pem();
        if (!load_cert_and_key_into_context(ssl_ctx, pem.second, pem.first))
        {
            spdlog::error("Failed to load certificate into SSL context");
            return EXIT_FAILURE;
        }

        spdlog::info("Self-signed certificate generated (in memory)");

        // --- Control acceptor ---
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), CONTROL_PORT));
        spdlog::info("Server started on port {} (TLS control)", CONTROL_PORT);

        start_control_accept(ssl_ctx, acceptor, data_servers, io, server_manager);

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

// ----------------------------------------------------------------------------
// Accept control connections
// ----------------------------------------------------------------------------
void start_control_accept(asio::ssl::context& ssl_ctx,
    tcp::acceptor& acceptor,
    std::shared_ptr<DataServers> data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager)
{
    auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io, ssl_ctx);

    acceptor.async_accept(ssl_sock->lowest_layer(),
        [ssl_sock, &acceptor, &ssl_ctx, data_servers, &io, server_manager](const asio::error_code& ec) mutable {
            if (!ec) {
                // Запускаем корутину в контексте io
                asio::co_spawn(io,
                    async_authorize(ssl_sock, data_servers, server_manager),
                    asio::detached);
            }
            else {
                spdlog::error("Accept error: {}", ec.message());
            }

            if (running) {
                start_control_accept(ssl_ctx, acceptor, data_servers, io, server_manager);
            }
        });
}

// ----------------------------------------------------------------------------
// Async authorization and GrayServer creation
// ----------------------------------------------------------------------------
asio::awaitable<void> async_authorize(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    std::shared_ptr<DataServers> data_servers,
    std::shared_ptr<ServerManager> server_manager)
{
    try {
        // 1. Handshake
        co_await ssl_sock->async_handshake(asio::ssl::stream_base::server, asio::use_awaitable);

        // 2. Читаем всё разом: ID (4 байта) + Pool Size (4 байта) = 8 байт
        struct { uint32_t id; uint32_t pool_size; } req;
        co_await asio::async_read(*ssl_sock, asio::buffer(&req, sizeof(req)), asio::use_awaitable);

        uint32_t id = ntohl(req.id);
        uint32_t pool_size = ntohl(req.pool_size);

        // 3. Проверка ID
        if (!data_servers->authorize_id(id)) {
            throw std::runtime_error("Unauthorized ID: " + std::to_string(id));
        }

        // 4. Логика создания сервера
        auto p = data_servers->get_ports_by_id(id);
        auto server = std::make_shared<GrayServer>(
            id, ssl_sock, co_await asio::this_coro::executor,
            p[0], p[1], pool_size, server_manager
        );

        // 5. Ответ клиенту (ID + порты для подтверждения)
        uint32_t resp[] = { htonl(id), htonl(p[0]), htonl(p[1]) };
        co_await asio::async_write(*ssl_sock, asio::buffer(resp), asio::use_awaitable);

        // 6. Регистрация и запуск
        server_manager->add(server);
        server->start();

    }
    catch (const std::exception& e) {
        spdlog::error("Authorization error: {}", e.what());
        asio::error_code ec;
        ssl_sock->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        ssl_sock->lowest_layer().close(ec);
    }
}