#include "Server_manager.h"
//=============ServerManager implementation=============
void ServerManager::add(std::shared_ptr<GrayServer> server) {
    std::lock_guard<std::mutex> lock(mtx_);
    servers.push_back(std::move(server));
}

void ServerManager::remove(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto before = servers.size();

    servers.erase(
        std::remove_if(
            servers.begin(),
            servers.end(),
            [id](const std::shared_ptr<GrayServer>& s) {
                return s && s->get_id() == id;
            }),
        servers.end()
    );

    if (before != servers.size()) {
        spdlog::info("GrayServer {} removed from manager", id);
    }
}

void ServerManager::shutdown_all() {
    std::vector<std::shared_ptr<GrayServer>> copy;

    {
        std::lock_guard<std::mutex> lock(mtx_);
        copy = servers;
        servers.clear();
    }

    for (auto& s : copy) {
        if (s) s->shutdown();
    }

    spdlog::info("All GrayServers shutdown requested");
}

bool ServerManager::shutdown_id(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);


    for (auto& server : servers) {
        if (server && server->get_id() == id) {
            server->shutdown();
            spdlog::info("GrayServer {} shutdown called", id);
            return true;
        }
    }

    spdlog::error("GrayServer {} not found in manager", id);
    return false;
}

bool ServerManager::server_online(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            return true;
        }
    }
    return false;
}

uint32_t ServerManager::get_ping(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    uint32_t ping = -1;
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            ping = s->get_ping();
        }
    }
    return ping;
}

uint32_t ServerManager::get_active_pairs(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            return s->get_active_pairs();
        }
    }
    return -1;
}
//===================================================

void ServerManager::start_up_tls() {
    auto self = shared_from_this();
    self->ssl_ctx.set_options(
        asio::ssl::context::default_workarounds
        | asio::ssl::context::no_sslv2
        | asio::ssl::context::no_sslv3
        | asio::ssl::context::single_dh_use
    );

    auto pem = generate_self_signed_cert_pem();
    if (!load_cert_and_key_into_context(self->ssl_ctx, pem.second, pem.first))
    {
        spdlog::error("Failed to load certificate into SSL context");
        return;
    }

    spdlog::info("Self-signed certificate generated (in memory)");

  
}
//===================================================
void ServerManager::init_acceptor() {
    control_acceptor = std::make_shared<tcp::acceptor>(io_context_, tcp::endpoint(tcp::v4(), control_port));
    data_acceptor = std::make_shared<tcp::acceptor>(io_context_, tcp::endpoint(tcp::v4(), data_port));
    spdlog::info("Data acceptor started on port {}", data_port);
    spdlog::info("Control acceptor started on port {}", control_port);
}
//===================================================
void ServerManager::async_accept_data() {
    auto self = shared_from_this();
    if (!running) return;

    auto sock = std::make_shared<asio::ip::tcp::socket>(io_context_);

    data_acceptor->async_accept(*sock,
        [self, sock](const asio::error_code& ec) {
            if (!ec) {
                
                asio::error_code endpoint_ec;
                auto remote = sock->remote_endpoint(endpoint_ec);
                std::string addr = endpoint_ec ? "unknown" : remote.address().to_string();

                spdlog::info("New data connection accepted from {}", addr);
                self->handle_new_data(sock);
            }

            
            if (self->running) {
                self->async_accept_data();
            }
        });
}

void ServerManager::handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto self = shared_from_this();

    
    asio::error_code endpoint_ec;
    auto remote = sock->remote_endpoint(endpoint_ec);
    spdlog::info("Handling new data connection from {}", endpoint_ec ? "unknown" : remote.address().to_string());

    auto buf = std::make_shared<DATA_PACKET>();

    
    asio::async_read(*sock, asio::buffer(buf.get(), sizeof(DATA_PACKET)),
        [self, sock, buf](const asio::error_code& ec, std::size_t bytes_read) {
            if (!self->running) return;

            if (ec || bytes_read != sizeof(DATA_PACKET)) {
                spdlog::warn("Failed to read DATA_PACKET: {}", ec.message());
                asio::error_code ignored;
                sock->close(ignored);
                return;
            }

            
            uint32_t id = ntohl(buf->id);
            uint32_t otp = ntohl(buf->otp);
            spdlog::info("Received data packet for server ID: {}, OTP: {}", id, otp);
            { 
                std::lock_guard<std::mutex> lock(self->mtx_);
                if (self->server_online(id)) {

                    for (auto& s : self->servers) {
                        if (s && s->get_id() == id) {
                            spdlog::info("Forwarding data connection to GrayServer {}", id);
                            s->handle_new_data(sock, otp);
                            return;
                        }
                    }
                }
                else {
                    spdlog::warn("Received data packet for unknown server ID: {}", id);
                    asio::error_code ignored;
                    sock->close(ignored);
                }
            }
            
        });
}
//
void ServerManager::async_accept_control() {
    auto self = shared_from_this();


    auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io_context_, ssl_ctx);

    control_acceptor->async_accept(ssl_sock->lowest_layer(),
        [self, ssl_sock](const asio::error_code& ec) {
            if (!self->running) return;

            if (!ec) {
                ssl_sock->async_handshake(asio::ssl::stream_base::server,
                    [self, ssl_sock](const asio::error_code& h_ec) {
                        if (!h_ec) {

                            asio::co_spawn(self->io_context_,
                                self->async_authorize(ssl_sock), asio::detached);
                        }
                        else {
                            spdlog::error("TLS handshake failed: {}", h_ec.message());
                        }
                    });
            }
            else {
                spdlog::error("Accept error: {}", ec.message());
            }


            self->async_accept_control();
        });
}
//===========
asio::awaitable<void> ServerManager::async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock)
{
    auto self = shared_from_this();
    try {
        

        //  Wait for request
        struct { uint32_t id; uint32_t pool_size; } req;
        co_await asio::async_read(*ssl_sock, asio::buffer(&req, sizeof(req)), asio::use_awaitable);

        uint32_t id = ntohl(req.id);
        uint32_t pool_size = ntohl(req.pool_size);

        //  Check authorization
        if (auto shared_data = data_servers.lock())
        {
            if (shared_data->authorize_id(id)) {

                auto p = shared_data->get_ports_by_id(id);
                auto server = std::make_shared<GrayServer>(
                    id, ssl_sock, co_await asio::this_coro::executor,
                    p, data_port, pool_size, self
                );

                //  Send response with ports
                uint32_t resp[] = { htonl(id), htonl(p), htonl(data_port) };
                co_await asio::async_write(*ssl_sock, asio::buffer(resp), asio::use_awaitable);

                // Add to manager and start
                self->add(server);
                server->start();

				spdlog::info("GrayServer {} authorized and started with pool size {}", id, pool_size);
            }

        }
        else {
            throw std::runtime_error("DataServers instance no longer exists");
        }

    }
    catch (const std::exception& e) {
        spdlog::error("Authorization error: {}", e.what());
        asio::error_code ec;
        ssl_sock->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        ssl_sock->lowest_layer().close(ec);
    }
}
