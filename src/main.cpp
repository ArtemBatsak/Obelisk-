#include <iostream>
#include <thread>
#include <vector>
#include <atomic>
#include <memory>
#include <array>
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

using asio::ip::tcp;

std::atomic<bool> running(true);
const int CONTROL_PORT = 44555;

struct Ports {
    uint32_t data_port;
    uint32_t client_port;
};

// Forward declarations
void command_thread(DataServers& data_servers, asio::io_context& io, ServerManager& server_manager);
void start_control_accept(asio::ssl::context& ssl_ctx, tcp::acceptor& acceptor, DataServers& data_servers, asio::io_context& io, std::shared_ptr<ServerManager> server_manager);
void async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock, DataServers& data_servers, asio::io_context& io, std::shared_ptr<ServerManager> server_manager);

int main() {
   
    try {
        init_logging();
        spdlog::info("Obelisk started");

        asio::io_context io;
        DataServers data_servers;
        auto server_manager = std::make_shared<ServerManager>();

        // --- Cross-platform signal handling ---
        asio::signal_set signals(io);
#ifdef _WIN32
        signals.add(SIGINT); // Ctrl+C
#else
        signals.add(SIGINT);
        signals.add(SIGTERM);
#endif
        signals.async_wait([&](const asio::error_code&, int) {
            spdlog::info("\nShutdown signal received, stopping the Obelisk...");
            running = false;
            server_manager->shutdown_all();
            io.stop();
            });

        // --- TLS context ---
        asio::ssl::context ssl_ctx(asio::ssl::context::tls_server);
        ssl_ctx.set_options(asio::ssl::context::default_workarounds
            | asio::ssl::context::no_sslv2
            | asio::ssl::context::no_sslv3
            | asio::ssl::context::single_dh_use);

        auto pem = generate_self_signed_cert_pem();
        if (!load_cert_and_key_into_context(ssl_ctx, pem.second, pem.first)) {
            spdlog::error("Failed to load certificate into SSL context");
            return 1;
        }
        spdlog::info("Self-signed certificate generated (in memory)");

        // --- Control port acceptor ---
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), CONTROL_PORT));
        spdlog::info("Server started on port {} (TLS control)", CONTROL_PORT);
        start_control_accept(ssl_ctx, acceptor, data_servers, io, server_manager);

        // --- Thread pool for io_context ---
        int num_threads = std::thread::hardware_concurrency();
        if (num_threads == 0) num_threads = 1;

        std::vector<std::thread> threads;
        threads.reserve(num_threads);
        for (int i = 0; i < num_threads; ++i)
            threads.emplace_back([&io]() { io.run(); });

        // --- Command thread ---
        std::thread cmd_thread([&data_servers, &io, server_manager]() {
            command_thread(data_servers, io, *server_manager);
            });

        for (auto& t : threads) t.join();
        cmd_thread.join();

        spdlog::info("Obelisk has stopped");
    }
    catch (const std::exception& e) {
        spdlog::error("Exception: {}", e.what());
    }

    return 0;
}

// ----------------------------------------------------------------------------
// Accept control connections
// ----------------------------------------------------------------------------
void start_control_accept(asio::ssl::context& ssl_ctx,
    tcp::acceptor& acceptor,
    DataServers& data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager)
{
    auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io, ssl_ctx);

    acceptor.async_accept(ssl_sock->lowest_layer(),
        [ssl_sock, &acceptor, &ssl_ctx, &data_servers, &io, server_manager](const asio::error_code& ec) mutable {
            if (!ec) {
                async_authorize(ssl_sock, data_servers, io, server_manager);
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
void async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
    DataServers& data_servers,
    asio::io_context& io,
    std::shared_ptr<ServerManager> server_manager)
{
    auto self = ssl_sock;
    auto close_socket = [self](const std::string& msg) {
        spdlog::error("{}", msg);
        asio::error_code ec;
        self->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        self->lowest_layer().close(ec);
        };

    self->async_handshake(asio::ssl::stream_base::server,
        [self, &data_servers, &io, close_socket, server_manager](const asio::error_code& ec)
        {
            if (ec) {
                close_socket(std::string("Handshake failed: ") + ec.message());
                return;
            }

            auto buf_id = std::make_shared<uint32_t>();
            asio::async_read(*self, asio::buffer(buf_id.get(), sizeof(uint32_t)),
                [self, buf_id, &data_servers, &io, close_socket, server_manager](const asio::error_code& ec, std::size_t)
                {
                    if (ec) {
                        close_socket(std::string("Failed to read ID: ") + ec.message());
                        return;
                    }

                    uint32_t id = ntohl(*buf_id);
                    if (!data_servers.authorize_id(id)) {
                        close_socket(std::string("Unauthorized ID: ") + std::to_string(id));
                        return;
                    }

                    auto ok = std::make_shared<uint32_t>(htonl(1));
                    asio::async_write(*self, asio::buffer(ok.get(), sizeof(uint32_t)),
                        [self, ok, &data_servers, &io, close_socket, server_manager, id](const asio::error_code& ec, std::size_t)
                        {
                            if (ec) {
                                close_socket(std::string("Failed to send OK after ID: ") + ec.message());
                                return;
                            }

                            auto buf_pool = std::make_shared<uint32_t>();
                            asio::async_read(*self, asio::buffer(buf_pool.get(), sizeof(uint32_t)),
                                [self, buf_pool, &data_servers, &io, close_socket, server_manager, id](const asio::error_code& ec, std::size_t)
                                {
                                    if (ec) {
                                        close_socket(std::string("Failed to read pool size: ") + ec.message());
                                        return;
                                    }

                                    uint32_t pool_size = ntohl(*buf_pool);
                                    spdlog::info("ID {} pool size = {}", id, pool_size);

                                    Ports ports;
                                    try {
                                        auto p = data_servers.get_ports_by_id(id);
                                        ports.data_port = p[0];
                                        ports.client_port = p[1];

                                        auto server = std::make_shared<GrayServer>(
                                            id,
                                            self,
                                            io,
                                            ports.client_port,
                                            ports.data_port,
                                            pool_size,
                                            server_manager
                                        );

                                        auto buf_resp = std::make_shared<std::array<uint32_t, 3>>();
                                        (*buf_resp)[0] = htonl(1);
                                        (*buf_resp)[1] = htonl(ports.data_port);
                                        (*buf_resp)[2] = htonl(ports.client_port);

                                        asio::async_write(*self, asio::buffer(*buf_resp),
                                            [self, buf_resp](const asio::error_code& ec, std::size_t)
                                            {
                                                if (ec) {
                                                    spdlog::error("Failed to send OK+ports: {}", ec.message());
                                                }
                                            });

                                        server_manager->add(server);
                                        server->start();
                                    }
                                    catch (const std::exception& e) {
                                        close_socket(std::string("Failed to create GrayServer: ") + std::string(e.what()));
                                        return;
                                    }
                                });
                        });
                });
        });
}

// ----------------------------------------------------------------------------
// Command thread
// ----------------------------------------------------------------------------
void command_thread(DataServers& data_servers, asio::io_context& io, ServerManager& server_manager) {
    while (running) {
        std::string cmd;
        std::getline(std::cin, cmd);
        if (!running) break;

        if (cmd == "/add") {
            data_servers.add_id();
        }
        else if (cmd == "/show") {
            data_servers.show_id();
        }
        else if (cmd == "/delete") {
            try { data_servers.delete_id(); }
            catch (const std::exception& e) { spdlog::error("Delete error: {}", e.what()); }
        }
        else if (cmd == "/shutdown") {
            spdlog::info("Shutting down Obelisk...");
            running = false;
            server_manager.shutdown_all();
            io.stop();
        }
        else {
            spdlog::info("Unknown command");
        }
    }
}
