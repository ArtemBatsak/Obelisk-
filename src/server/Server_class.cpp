#include "Server_class.h"
#include "logger/Logger.h"
#include <openssl/rand.h>
#include <stdexcept>
#include <cstring>

void GrayServer::init_acceptor(int client_port) {
    client_acceptor_ = std::make_shared<asio::ip::tcp::acceptor>(
        io_context_,
        asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port));
}

void GrayServer::purge_expired_otps() {
    const auto now = Clock::now();
    otp_pool.erase(
        std::remove_if(otp_pool.begin(), otp_pool.end(),
            [&now](const OtpEntry& e) { return now >= e.expires_at; }),
        otp_pool.end());
}

void GrayServer::purge_idle_pending() {
    const auto now = Clock::now();
    asio::error_code ec;

    auto purge = [&](std::vector<PendingSocket>& pool, const char* kind) {
        auto it = pool.begin();
        while (it != pool.end()) {
            const bool timed_out = (now - it->accepted_at) >= pending_idle_timeout_;
            const bool closed = !it->sock || !it->sock->is_open();
            if (timed_out || closed) {
                if (timed_out && it->sock && it->sock->is_open()) {
                    spdlog::warn("Server {}: closing idle pending {} socket", id, kind);
                    it->sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
                    it->sock->close(ec);
                }
                it = pool.erase(it);
            }
            else {
                ++it;
            }
        }
    };

    purge(client_pool, "client");
    purge(data_pool, "data");
}

std::size_t GrayServer::otp_pool_cap() const {
    return static_cast<std::size_t>(std::min(pool_size * 2, 128));
}

void GrayServer::handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t otp) {
    auto self = shared_from_this();
    asio::post(strand_, [self, sock, otp]() {
        if (!self->alive) return;

        asio::error_code endpoint_ec;
        auto remote = sock->remote_endpoint(endpoint_ec);
        if (endpoint_ec) {
            spdlog::warn("Server {}: rejecting data socket without remote endpoint", self->id);
            asio::error_code ignored;
            sock->close(ignored);
            return;
        }

        if (!self->allowed_data_ip_ || remote.address() != *self->allowed_data_ip_) {
            spdlog::warn("Server {}: rejecting data socket from unexpected IP {} (allowed {})",
                self->id,
                remote.address().to_string(),
                self->allowed_data_ip_ ? self->allowed_data_ip_->to_string() : "unset");
            asio::error_code ignored;
            sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
            sock->close(ignored);
            return;
        }

        self->purge_expired_otps();

        bool otp_valid = false;
        auto it = std::find_if(self->otp_pool.begin(), self->otp_pool.end(),
            [otp](const OtpEntry& e) { return e.value == otp; });
        if (it != self->otp_pool.end()) {
            otp_valid = true;
            self->otp_pool.erase(it);
        }

        if (!otp_valid) {
            spdlog::warn("Server {}: rejecting data socket due to invalid or expired OTP",
                self->id);
            asio::error_code ignored;
            sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
            sock->close(ignored);
            return;
        }

        self->enable_keepalive(sock);
        self->data_pool.push_back(PendingSocket{ sock, Clock::now() });
        self->try_create_pair();
    });
}

uint32_t GrayServer::generate_otp() {
    uint32_t raw = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&raw), sizeof(raw)) != 1) {
        spdlog::error("Server {}: RAND_bytes failed while generating OTP", id);
        throw std::runtime_error("RAND_bytes failed");
    }
    return 100000u + (raw % 900000u);
}

void GrayServer::check_data_pool() {
    auto self = shared_from_this();
    if (!self->alive || self->check_in_progress) return;
    self->check_in_progress = true;

    self->purge_expired_otps();
    self->purge_idle_pending();

    auto it = self->data_pool.begin();
    while (it != self->data_pool.end()) {
        if (!it->sock || !it->sock->is_open()) it = self->data_pool.erase(it);
        else ++it;
    }

    const bool need_more_data =
        self->data_pool.size() < static_cast<std::size_t>(self->pool_size);
    const bool otp_room = self->otp_pool.size() < self->otp_pool_cap();

    if (need_more_data && otp_room) {
        bool otp_ready = false;
        try {
            self->current_otp = generate_otp();
            otp_ready = true;
        }
        catch (const std::exception& e) {
            spdlog::error("Server {}: OTP generation failed: {}", self->id, e.what());
        }

        if (otp_ready && self->control_socket && self->control_socket->lowest_layer().is_open()) {
            self->otp_pool.push_back(OtpEntry{ self->current_otp, Clock::now() + otp_ttl_ });
            send_control_packet(2, self->current_otp,
                [self](const asio::error_code& ec) {
                    if (ec) {
                        spdlog::error("Server {}: failed to send OTP control packet (code {}): {}", self->id, ec.value(), ec.message());
                    }
                    self->check_in_progress = false;
                });
        }
        else {
            self->check_in_progress = false;
        }
    }
    else {
        self->check_in_progress = false;
    }

    self->data_pool_timer.expires_after(std::chrono::seconds(2));
    self->data_pool_timer.async_wait(
        asio::bind_executor(self->strand_, [self](const asio::error_code& ec) {
            if (!self->alive || ec == asio::error::operation_aborted) return;
            self->check_data_pool();
        }));
}

void GrayServer::enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock) {
    asio::error_code ec;
    sock->set_option(asio::socket_base::keep_alive(true), ec);
    if (ec) {
        spdlog::error("Server {}: set_option keep_alive failed (code {}): {}", id, ec.value(), ec.message());
        return;
    }

    sock->set_option(asio::ip::tcp::no_delay(true), ec);
    if (ec) {
        spdlog::error("Server {}: set_option no_delay failed (code {}): {}", id, ec.value(), ec.message());
    }

#ifdef _WIN32
    tcp_keepalive ka;
    ka.onoff = 1;
    ka.keepalivetime = 20000;
    ka.keepaliveinterval = 5000;
    DWORD bytesReturned;
    WSAIoctl(sock->native_handle(), SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytesReturned, nullptr, nullptr);
#else
    int idle = 20;
    int interval = 5;
    int count = 3;
    int fd = sock->native_handle();
    setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
    setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
    setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
}

void GrayServer::shutdown() {
    auto self = shared_from_this();
    asio::post(strand_, [self]() {
        if (!self->alive) return;
        self->alive = false;

        self->ping_timer.cancel();
        self->pong_timer.cancel();
        self->data_pool_timer.cancel();
        self->speed_monitor_timer.cancel();

        asio::error_code ec;

        if (self->client_acceptor_ && self->client_acceptor_->is_open())
            self->client_acceptor_->close(ec);

        if (self->control_socket && self->control_socket->lowest_layer().is_open()) {
            self->control_socket->lowest_layer().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
            self->control_socket->lowest_layer().close(ec);
        }

        self->remove_all_pairs();

        for (auto& s : self->data_pool) {
            if (s.sock && s.sock->is_open()) s.sock->close(ec);
        }
        self->data_pool.clear();

        for (auto& s : self->client_pool) {
            if (s.sock && s.sock->is_open()) s.sock->close(ec);
        }
        self->client_pool.clear();
        self->otp_pool.clear();

        if (auto mgr = self->manager_.lock()) {
            mgr->remove(self->id);
        }
    });
}

void GrayServer::send_ping() {
    auto self = shared_from_this();
    if (!self->alive || !self->control_socket || !self->control_socket->lowest_layer().is_open())
        return;

    if (self->waiting_for_pong) {
        spdlog::warn("Server {}: send_ping skipped because a pong is already awaited", self->id);
        return;
    }
    self->waiting_for_pong = true;

    send_control_packet(1, 0, [self](const asio::error_code& ec) {
        if (ec) {
            spdlog::error("Server {}: send_ping failed (code {}): {}", self->id, ec.value(), ec.message());
            self->waiting_for_pong = false;
            self->shutdown();
            return;
        }
        self->last_ping_start_ = Clock::now();
        self->wait_pong();
    });
}

void GrayServer::wait_pong() {
    auto self = shared_from_this();
    if (!self->alive || !self->control_socket || !self->control_socket->lowest_layer().is_open())
        return;

    self->pong_timer.cancel();
    self->pong_timer.expires_after(std::chrono::seconds(self->ping_timeout_sec));
    self->pong_timer.async_wait(
        asio::bind_executor(self->strand_, [self](const asio::error_code& ec) {
            if (ec == asio::error::operation_aborted || !self->alive) return;

            spdlog::error("Server {}: pong timeout, closing control socket", self->id);
            asio::error_code ignored;
            self->control_socket->lowest_layer().close(ignored);
            self->waiting_for_pong = false;
        }));

    asio::async_read(*self->control_socket, asio::buffer(self->pong_buf),
        asio::bind_executor(self->strand_, [self](const asio::error_code& ec, std::size_t bytes_transferred) {
            if (!self->alive) { self->waiting_for_pong = false; return; }

            if (ec) {
                if (ec != asio::error::eof) {
                    spdlog::error("Server {}: control read error (code {}): {}", self->id, ec.value(), ec.message());
                }
                self->waiting_for_pong = false;
                self->shutdown();
                return;
            }

            if (bytes_transferred < sizeof(Packet)) {
                spdlog::warn("Server {}: received incomplete control packet: {} bytes", self->id, bytes_transferred);
                self->waiting_for_pong = false;
                self->shutdown();
                return;
            }

            Packet pkt;
            std::memcpy(&pkt, self->pong_buf.data(), sizeof(Packet));

            auto elapsed = Clock::now() - self->last_ping_start_;
            self->last_ping_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
            self->last_ping_ms = static_cast<uint32_t>(self->last_ping_ms_.count());

            self->waiting_for_pong = false;
            self->pong_timer.cancel();
            self->schedule_ping();
        }));
}

void GrayServer::schedule_ping() {
    auto self = shared_from_this();
    self->ping_timer.cancel();
    self->ping_timer.expires_after(std::chrono::seconds(ping_interval_sec));
    self->ping_timer.async_wait(
        asio::bind_executor(strand_, [self](const asio::error_code& ec) {
            if (!self->alive || ec == asio::error::operation_aborted) return;
            self->send_ping();
        }));
}

void GrayServer::async_accept_client() {
    auto self = shared_from_this();
    if (!self->alive) return;

    auto sock = std::make_shared<asio::ip::tcp::socket>(io_context_);

    client_acceptor_->async_accept(*sock,
        asio::bind_executor(strand_, [self, sock](const asio::error_code& ec) {
            if (!self->alive || !self->client_acceptor_ || !self->client_acceptor_->is_open()) return;

            if (!ec) {
                self->purge_idle_pending();
                if (self->client_pool.size() >= static_cast<std::size_t>(self->max_pending_clients)) {
                    spdlog::warn("Server {}: client_pool full ({}), rejecting connection",
                        self->id, self->max_pending_clients);
                    asio::error_code ignored;
                    sock->close(ignored);
                }
                else {
                    self->client_pool.push_back(PendingSocket{ sock, Clock::now() });
                    self->try_create_pair();
                }
            }
            self->async_accept_client();
        }));
}

std::string GrayServer::generate_id(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto endpoint = sock->remote_endpoint();
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

void GrayServer::try_create_pair() {
    if (client_pool.empty() || data_pool.empty()) return;

    auto client_pending = client_pool.back();
    client_pool.pop_back();
    auto client_sock = client_pending.sock;

    auto it = std::find_if(data_pool.begin(), data_pool.end(),
        [](const PendingSocket& s) { return s.sock && s.sock->is_open(); });
    if (it == data_pool.end()) {
        client_pool.push_back(client_pending);
        return;
    }

    auto data_sock = it->sock;
    data_pool.erase(it);

    auto pair = std::make_shared<link_par>();
    pair->client_socket = client_sock;
    pair->data_socket = data_sock;
    pair->pair_id = generate_id(client_sock);
    link_pool.push_back(pair);
    active_pairs_count_.store(link_pool.size(), std::memory_order_release);

    enable_keepalive(client_sock);
    enable_keepalive(data_sock);

    splice_loop(client_sock, data_sock, pair, true);
    splice_loop(data_sock, client_sock, pair, false);
    check_data_pool();
}

void GrayServer::splice_loop(
    std::shared_ptr<asio::ip::tcp::socket> in_sock,
    std::shared_ptr<asio::ip::tcp::socket> out_sock,
    std::shared_ptr<link_par> pair,
    bool is_inbound)
{
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<char, 64 * 1024>>();
    auto do_read = std::make_shared<std::function<void()>>();

    *do_read = [self, in_sock, out_sock, pair, buffer, is_inbound, do_read]() mutable {
        in_sock->async_read_some(asio::buffer(*buffer),
            [self, in_sock, out_sock, pair, buffer, is_inbound, do_read]
            (const asio::error_code& ec, std::size_t bytes) {
                if (ec || bytes == 0) {
                    *do_read = nullptr;
                    asio::post(self->strand_, [self, id = pair->pair_id]() {
                        self->remove_pair(id);
                    });
                    return;
                }

                if (is_inbound) pair->trafic_in += bytes;
                else pair->trafic_out += bytes;

                asio::async_write(*out_sock, asio::buffer(buffer->data(), bytes),
                    [self, pair, do_read](const asio::error_code& ec_write, std::size_t) {
                        if (ec_write) {
                            *do_read = nullptr;
                            asio::post(self->strand_, [self, id = pair->pair_id]() {
                                self->remove_pair(id);
                            });
                            return;
                        }
                        (*do_read)();
                    });
            });
    };

    (*do_read)();
}

void GrayServer::remove_pair(const std::string& pair_id) {
    auto it = std::find_if(link_pool.begin(), link_pool.end(),
        [&pair_id](const std::shared_ptr<link_par>& ptr) {
            return ptr && ptr->pair_id == pair_id;
        });

    if (it == link_pool.end()) return;

    auto client_sock = (*it)->client_socket;
    auto data_sock = (*it)->data_socket;
    link_pool.erase(it);
    active_pairs_count_.store(link_pool.size(), std::memory_order_release);

    if (client_sock && client_sock->is_open()) {
        asio::error_code ec;
        client_sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        client_sock->close(ec);
    }
    if (data_sock && data_sock->is_open()) {
        asio::error_code ec;
        data_sock->shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        data_sock->close(ec);
    }
}

void GrayServer::remove_all_pairs() {
    while (!link_pool.empty()) {
        auto target_id = link_pool.back()->pair_id;
        remove_pair(target_id);
    }
    spdlog::info("Server {}: all pairs have been removed", id);
}

void GrayServer::send_control_packet(uint32_t type, uint32_t value,
    std::function<void(const asio::error_code&)> handler) {
    if (!alive || !control_socket || !control_socket->lowest_layer().is_open()) {
        spdlog::error("Server {}: send_control_packet failed: control socket is not available", id);
        if (handler) handler(asio::error::make_error_code(asio::error::operation_aborted));
        return;
    }
    auto pkt = std::make_shared<Packet>();
    pkt->type = htonl(type);
    pkt->value = htonl(value);

    asio::async_write(*control_socket, asio::buffer(pkt.get(), sizeof(Packet)),
        asio::bind_executor(strand_, [self = shared_from_this(), pkt, handler](const asio::error_code& ec, std::size_t) {
            if (ec) {
                spdlog::error("Server {}: send_control_packet failed (code {}): {}", self->id, ec.value(), ec.message());
                self->shutdown();
            }
            if (handler) handler(ec);
        }));
}

void GrayServer::start() {
    auto self = shared_from_this();
    asio::post(strand_, [self]() {
        if (!self->alive) return;

        if (!self->allowed_data_ip_ && self->control_socket) {
            asio::error_code ec;
            auto ep = self->control_socket->lowest_layer().remote_endpoint(ec);
            if (!ec) {
                self->allowed_data_ip_ = ep.address();
            }
        }
        if (self->allowed_data_ip_) {
            spdlog::info("Server {}: data sockets allowed only from {}",
                self->id, self->allowed_data_ip_->to_string());
        }
        else {
            spdlog::warn("Server {}: allowed data IP unset; data sockets will be rejected",
                self->id);
        }

        self->init_acceptor(self->client_port);
        self->async_accept_client();
        self->check_data_pool();
        self->schedule_ping();
        self->start_speed_monitor();
    });
}

void GrayServer::start_speed_monitor() {
    if (!alive || speed_monitor_running) return;
    speed_monitor_running = true;
    last_measure_time = std::chrono::steady_clock::now();
    schedule_speed_monitor();
}

void GrayServer::schedule_speed_monitor() {
    auto self = shared_from_this();
    self->speed_monitor_timer.expires_after(std::chrono::seconds(1));

    self->speed_monitor_timer.async_wait(
        asio::bind_executor(self->strand_, [self](const asio::error_code& ec) {
            if (ec || !self->alive) {
                self->speed_monitor_running = false;
                return;
            }

            auto now = std::chrono::steady_clock::now();
            double seconds = std::chrono::duration<double>(now - self->last_measure_time).count();
            self->last_measure_time = now;

            if (seconds < 1e-6) {
                self->schedule_speed_monitor();
                return;
            }

            uint64_t total_bytes_in = 0;
            uint64_t total_bytes_out = 0;

            for (auto& pair : self->link_pool) {
                if (!pair) continue;

                uint64_t current_in = pair->trafic_in.load(std::memory_order_relaxed);
                uint64_t current_out = pair->trafic_out.load(std::memory_order_relaxed);

                uint64_t delta_in = 0;
                uint64_t delta_out = 0;

                if (current_in >= pair->last_in_snapshot)
                    delta_in = current_in - pair->last_in_snapshot;
                if (current_out >= pair->last_out_snapshot)
                    delta_out = current_out - pair->last_out_snapshot;

                total_bytes_in += delta_in;
                total_bytes_out += delta_out;

                pair->last_in_snapshot = current_in;
                pair->last_out_snapshot = current_out;
            }

            double speed_in = total_bytes_in / seconds;
            double speed_out = total_bytes_out / seconds;

            self->total_speed_in.store(static_cast<uint64_t>(speed_in), std::memory_order_relaxed);
            self->total_speed_out.store(static_cast<uint64_t>(speed_out), std::memory_order_relaxed);
            self->total_traffic_session += total_bytes_in + total_bytes_out;
            self->schedule_speed_monitor();
        }));
}
