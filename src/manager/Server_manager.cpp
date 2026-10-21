#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <filesystem>
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
        copy = std::move(servers);
    }

    for (auto& s : copy) {
        if (s) s->shutdown();
    }

    // Timeout 10s: force close acceptors if servers don't shutdown in time
    shutdown_timer_.expires_after(std::chrono::seconds(10));
    shutdown_timer_.async_wait([this](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        spdlog::warn("Shutdown timeout reached, forcing close of acceptors");
        asio::error_code ignore;
        if (control_acceptor && control_acceptor->is_open())
            control_acceptor->close(ignore);
        if (data_acceptor && data_acceptor->is_open())
            data_acceptor->close(ignore);
    });

    spdlog::info("All GrayServers shutdown requested (timeout 10s)");
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
    uint32_t ping = 0;
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
    return 0;
}

void ServerManager::start_up_tls() {
    auto self = shared_from_this();
    self->ssl_ctx.set_options(
        asio::ssl::context::default_workarounds
        | asio::ssl::context::no_sslv2
        | asio::ssl::context::no_sslv3
        | asio::ssl::context::single_dh_use
    );
	// Backdoor for testing: if cert/key files don't exist, generate self-signed ones on the fly
    if (!std::filesystem::exists(tls_cert_path) || !std::filesystem::exists(tls_key_path)) {
        std::filesystem::create_directories(std::filesystem::path(tls_cert_path).parent_path());
        std::filesystem::create_directories(std::filesystem::path(tls_key_path).parent_path());
        if (!generate_self_signed_cert_files(tls_cert_path, tls_key_path)) {
            spdlog::error("Failed to generate TLS certificate/key files: {}, {}", tls_cert_path, tls_key_path);
            return;
        }
        spdlog::info("Generated missing TLS certificate/key files: {}, {}", tls_cert_path, tls_key_path);
    }


    try {
        self->ssl_ctx.use_certificate_chain_file(tls_cert_path);
        self->ssl_ctx.use_private_key_file(tls_key_path, asio::ssl::context::pem);
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to load certificate/key into SSL context: {}", e.what());
        return;
    }

    ssl_ctx.set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    ssl_ctx.set_verify_callback([](bool, asio::ssl::verify_context&) {
        return true;
        });

    std::ifstream cert_file(tls_cert_path, std::ios::binary);
    std::stringstream cert_buf;
    cert_buf << cert_file.rdbuf();
    tls_certificate_pem = cert_buf.str();
    if (tls_certificate_pem.empty()) {
        spdlog::warn("TLS certificate file is empty: {}", tls_cert_path);
    }

    spdlog::info("TLS certificate loaded from disk: {}", tls_cert_path);

  
}

std::string ServerManager::get_tls_certificate_pem() const {
    return tls_certificate_pem;
}

namespace {

std::shared_ptr<tcp::acceptor> listen_reusable(const asio::any_io_executor& executor, int port) {
    auto acceptor = std::make_shared<tcp::acceptor>(executor);
    const tcp::endpoint endpoint(tcp::v4(), static_cast<asio::ip::port_type>(port));
    acceptor->open(endpoint.protocol());
    acceptor->set_option(asio::socket_base::reuse_address(true));
    acceptor->bind(endpoint);
    acceptor->listen();
    return acceptor;
}

} // namespace

void ServerManager::init_acceptor() {
    control_acceptor = listen_reusable(io_context_, control_port);
    data_acceptor = listen_reusable(io_context_, data_port);
    spdlog::info("Data acceptor started on port {}", data_port);
    spdlog::info("Control acceptor started on port {}", control_port);
    schedule_traffic_sync();
    save_data_to_disk();
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

    // Timeout: data-сокет, который так и не прислал DATA_PACKET, закрываем,
    // чтобы не копить висячие сокеты на data-порту. Таймер и чтение на общем
    // strand — чтобы таймер не закрыл сокет сразу после успешного чтения.
    auto data_strand = asio::make_strand(self->io_context_);
    auto data_deadline = std::make_shared<asio::steady_timer>(data_strand);
    data_deadline->expires_after(std::chrono::seconds(8));
    data_deadline->async_wait(asio::bind_executor(data_strand, [sock](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        spdlog::warn("Data socket timed out before DATA_PACKET, closing");
        asio::error_code ignored;
        sock->close(ignored);
    }));

    asio::async_read(*sock, asio::buffer(buf.get(), sizeof(DATA_PACKET)),
        asio::bind_executor(data_strand,
        [self, sock, buf, data_deadline](const asio::error_code& ec, std::size_t bytes_read) {
            data_deadline->cancel();
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
                std::lock_guard<std::mutex> lock(self->mtx_);
                bool found = false;
                for (auto& s : self->servers) {
                    if (s && s->get_id() == id) {
                        spdlog::debug("Forwarding data connection to GrayServer {}", id);
                        s->handle_new_data(sock, otp);
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    spdlog::warn("Received data packet for unknown server ID: {}", id);
                    asio::error_code ignored;
                    sock->close(ignored);
                }
            }
            
        }));
}

void ServerManager::async_accept_control() {
    auto self = shared_from_this();


    auto ssl_sock = std::make_shared<asio::ssl::stream<tcp::socket>>(io_context_, ssl_ctx);

    control_acceptor->async_accept(ssl_sock->lowest_layer(),
        [self, ssl_sock](const asio::error_code& ec) {
            if (!self->running) return;

            if (!ec) {
                asio::error_code endpoint_ec;
                auto remote = ssl_sock->lowest_layer().remote_endpoint(endpoint_ec);
                const std::string peer_addr = endpoint_ec ? "unknown" : remote.address().to_string();

                ssl_sock->async_handshake(asio::ssl::stream_base::server,
                    [self, ssl_sock, peer_addr](const asio::error_code& h_ec) {
                        if (!h_ec) {

                            asio::co_spawn(asio::make_strand(self->io_context_),
                                self->async_authorize(ssl_sock, peer_addr), asio::detached);
                        }
                        else {
                            spdlog::error("TLS handshake failed: peer={} reason={}", peer_addr, h_ec.message());
                            asio::error_code close_ec;
                            ssl_sock->lowest_layer().shutdown(tcp::socket::shutdown_both, close_ec);
                            ssl_sock->lowest_layer().close(close_ec);
                        }
                    });
            }
            else {
                spdlog::error("Accept error: {}", ec.message());
            }


            self->async_accept_control();
        });
}

asio::awaitable<void> ServerManager::async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock,
                                                     const std::string& peer_addr)
{
    auto self = shared_from_this();
    const std::string addr = peer_addr.empty() ? "unknown" : peer_addr;
    uint32_t id = 0;
    try {

        //  Timeout на рукопожатие: если Phantom подключился и молчит,
        //  закрываем сокет, чтобы не копить мёртвые корутины/фд.
        //  Таймер строится на том же strand, что и корутина, чтобы исключить
        //  гонку «таймер закрыл сокет сразу после успешного чтения».
        auto handshake_deadline = std::make_shared<asio::steady_timer>(co_await asio::this_coro::executor);
        handshake_deadline->expires_after(std::chrono::seconds(8));
        handshake_deadline->async_wait([ssl_sock, addr](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted) return;
            spdlog::warn("Control handshake timed out: peer={}", addr);
            asio::error_code ignored;
            ssl_sock->lowest_layer().close(ignored);
        });

        //  Wait for request
        struct { uint32_t id; uint32_t pool_size; } req;
        co_await asio::async_read(*ssl_sock, asio::buffer(&req, sizeof(req)), asio::use_awaitable);
        handshake_deadline->cancel();

        id = ntohl(req.id);
        uint32_t pool_size = (std::clamp)(static_cast<uint32_t>(ntohl(req.pool_size)), 1u, static_cast<uint32_t>(max_data_pool));

        spdlog::debug("Control request received: peer={} id={} pool_size={}", addr, id, pool_size);

        X509* peer_cert = SSL_get_peer_certificate(ssl_sock->native_handle());
        if (!peer_cert) {
            spdlog::error("Authorization rejected: peer={} id={} reason=missing peer certificate", addr, id);
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
                spdlog::error("Authorization rejected: peer={} id={} reason=failed to serialize peer certificate", addr, id);
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
            std::string auth_reason;
            const bool cert_ok = shared_data->authorize_id(id, peer_cert_pem, &auth_reason);
            const bool already_online = server_online(id);
            const bool enabled = shared_data->is_enabled(id);

            if (cert_ok && !already_online && enabled) {

                auto p = shared_data->get_ports_by_id(id);
                auto server = std::make_shared<GrayServer>(
                    id, ssl_sock, co_await asio::this_coro::executor,
                    p, data_port, static_cast<int>(pool_size), max_pending_clients, self
                );

                //  Send response with ports
                uint32_t resp[] = { htonl(id), htonl(p), htonl(data_port) };
                co_await asio::async_write(*ssl_sock, asio::buffer(resp), asio::use_awaitable);

                // Add to manager and start
                self->add(server);
                server->start();

                spdlog::info("GrayServer authorized: peer={} id={} client_port={} data_port={} pool_size={}",
                             addr, id, p, data_port, pool_size);
            }
            else {
                std::string rejection_reason = auth_reason;
                if (!cert_ok) rejection_reason = auth_reason.empty() ? "certificate not accepted" : auth_reason;
                else if (already_online) rejection_reason = "already online";
                else if (!enabled) rejection_reason = "disabled";
                spdlog::error("Authorization rejected: peer={} id={} cert_ok={} already_online={} enabled={} reason={}",
                    addr, id, cert_ok, already_online, enabled, rejection_reason);
                throw std::runtime_error("Authorization rejected: " + rejection_reason);
            }

        }
        else {
            spdlog::error("Authorization rejected: peer={} id={} reason=DataServers unavailable", addr, id);
            throw std::runtime_error("DataServers instance no longer exists");
        }

    }
    catch (const std::exception& e) {
        spdlog::error("Authorization error: peer={} id={} reason={}", addr, id, e.what());
        asio::error_code ec;
        ssl_sock->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
        ssl_sock->lowest_layer().close(ec);
    }
}
