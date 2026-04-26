#include <openssl/pem.h>
#include <openssl/ssl.h>
#include "Server_manager.h"
//=============ServerManager implementation=============
void ServerManager::add(std::shared_ptr<GrayServer> server) {
    std::lock_guard<std::mutex> lock(mtx_);
    servers.push_back(std::move(server));
}

void ServerManager::remove(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);

    uint64_t traffic_total = 0;
    auto before = servers.size();

    servers.erase(
        std::remove_if(
            servers.begin(),
            servers.end(),
            [id, &traffic_total](const std::shared_ptr<GrayServer>& s) {
                if (s && s->get_id() == id) {
                    traffic_total = s->get_total_traffic();
                    return true;
                }
                return false;
            }),
        servers.end()
    );

    if (before != servers.size()) {
        if (auto data = data_servers.lock()) {
            data->updateServerTraffic(id, traffic_total);
			data->calculate_total_traffic(id);
        }
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

uint64_t ServerManager::get_total_traffic(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            return s->get_total_traffic();
        }
    }
    return 0;
}

uint64_t ServerManager::get_total_speed_in(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            return s->get_total_speed_in();
        }
    }
    return 0;
}

uint64_t ServerManager::get_total_speed_out(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers) {
        if (s && s->get_id() == id) {
            return s->get_total_speed_out();
        }
    }
    return 0;
}

bool ServerManager::delete_server(uint32_t id) {
    if (auto data = data_servers.lock()) {
        data->updateServerTraffic(id, get_total_traffic(id));
    }

    shutdown_id(id);
    if (auto data = data_servers.lock()) {
        return data->deleteServerById(id);
    }

    spdlog::error("DataServers instance no longer exists");
    return false;
}

void ServerManager::persist_online_traffic() {
    std::vector<std::pair<uint32_t, uint64_t>> traffic_snapshot;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (const auto& s : servers) {
            if (s) {
                traffic_snapshot.emplace_back(s->get_id(), s->get_total_traffic());
            }
        }
    }

    if (auto data = data_servers.lock()) {
        for (const auto& [id, total] : traffic_snapshot) {
            data->updateServerTraffic(id, total);
        }
    }
}

void ServerManager::schedule_traffic_sync() {
    auto self = shared_from_this();
    traffic_sync_timer.expires_after(traffic_sync_interval);
    traffic_sync_timer.async_wait([self](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted || !self->running || !self->running->load()) {
            return;
        }
        self->persist_online_traffic();
        self->schedule_traffic_sync();
        });
}

void ServerManager::save_data_to_disk() {
    save_data_timer.expires_after(save_data_interval);
    save_data_timer.async_wait([this](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted || !this->running || !this->running->load()) {
            return;
        }
		if (auto data = data_servers.lock()) {
            data->save_all();
            spdlog::info("DataServers state saved to disk");
            return;
        }
        else {
            spdlog::error("DataServers instance no longer exists, cannot save to disk");
			return;
        }
		
        });
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

    ssl_ctx.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    ssl_ctx.set_verify_callback([](bool, asio::ssl::verify_context&) {
        return true;
        });

    spdlog::info("Self-signed certificate generated (in memory)");

  
}

void ServerManager::init_acceptor() {
    control_acceptor = std::make_shared<tcp::acceptor>(io_context_, tcp::endpoint(tcp::v4(), control_port));
    data_acceptor = std::make_shared<tcp::acceptor>(io_context_, tcp::endpoint(tcp::v4(), data_port));
    spdlog::info("Data acceptor started on port {}", data_port);
    spdlog::info("Control acceptor started on port {}", control_port);
    schedule_traffic_sync();
}

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

                //spdlog::info("New data connection accepted from {}", addr);
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
    spdlog::debug("Handling new data connection from {}", endpoint_ec ? "unknown" : remote.address().to_string());

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
            spdlog::debug("Received data packet for server ID: {}, OTP: {}", id, otp);
            { 
                
                if (self->server_online(id)) {

                    std::lock_guard<std::mutex> lock(self->mtx_);
                    for (auto& s : self->servers) {
                        if (s && s->get_id() == id) {
                            spdlog::debug("Forwarding data connection to GrayServer {}", id);
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

asio::awaitable<void> ServerManager::async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock)
{
    auto self = shared_from_this();
    try {
        

        //  Wait for request
        struct { uint32_t id; uint32_t pool_size; } req;
        co_await asio::async_read(*ssl_sock, asio::buffer(&req, sizeof(req)), asio::use_awaitable);

        uint32_t id = ntohl(req.id);
        uint32_t pool_size = ntohl(req.pool_size);

        X509* peer_cert = SSL_get_peer_certificate(ssl_sock->native_handle());
        if (!peer_cert) {
            throw std::runtime_error("Client certificate is missing");
        }

        std::string peer_cert_pem;
        {
            BIO* cert_bio = BIO_new(BIO_s_mem());
            if (!cert_bio || PEM_write_bio_X509(cert_bio, peer_cert) != 1) {
                if (cert_bio) {
                    BIO_free(cert_bio);
                }
                X509_free(peer_cert);
                throw std::runtime_error("Failed to serialize client certificate");
            }

            char* cert_ptr = nullptr;
            long cert_len = BIO_get_mem_data(cert_bio, &cert_ptr);
            if (cert_len > 0 && cert_ptr) {
                peer_cert_pem.assign(cert_ptr, static_cast<size_t>(cert_len));
            }

            BIO_free(cert_bio);
        }
        X509_free(peer_cert);

        //  Check authorization
        if (auto shared_data = data_servers.lock())
        {
            if (shared_data->authorize_id(id, peer_cert_pem)) {

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
            else {
                throw std::runtime_error("Certificate mismatch or unknown server ID");
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
