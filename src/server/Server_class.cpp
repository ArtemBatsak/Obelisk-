#include "Server_class.h"
#include "logger/logger.h"

void GrayServer::init_acceptor(int client_port) {
    client_acceptor_ = std::make_shared<asio::ip::tcp::acceptor>(
        io_context_,
        asio::ip::tcp::endpoint(asio::ip::tcp::v4(), client_port));
}

void GrayServer::handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t otp) {
    auto self = shared_from_this();
    if (!self->alive) return;
    

            uint32_t received_otp = otp;
            bool otp_valid = false;
			
            {
                std::lock_guard<std::mutex> lock(otp_pool_mutex);
                auto it = std::find(otp_pool.begin(), otp_pool.end(), received_otp);
                if (it != otp_pool.end()) {
                    otp_valid = true;
                    otp_pool.erase(it); 
                }
            }

            if (!otp_valid) {
                spdlog::warn(
                    "Server {}: received OTP {} that is not in the pool; rejecting connection",
                    id, received_otp
				);
                try {
                    auto ep = sock->remote_endpoint();
                    spdlog::error(
                        "Server {}: received wrong OTP {} (not in pool) from {}:{}",
                        id, received_otp,
                        ep.address().to_string(), ep.port()
                    );
                }
                catch (...) {
                    spdlog::error(
                        "Server {}: received wrong OTP {} (not in pool); remote endpoint unavailable",
                        id, received_otp
                    );
                }

                asio::error_code ignored;
                sock->shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
                sock->close(ignored);
                return;
            }
            asio::error_code ka_ec;
            sock->set_option(asio::socket_base::keep_alive(true), ka_ec);
            if (ka_ec) {
                
                spdlog::error("Server {}: failed to set keepalive on data socket (code {}): {}", id, ka_ec.value(), ka_ec.message());
            }

            {
                std::lock_guard<std::mutex> lock(data_pool_mutex);
                data_pool.push_back(sock);
            }
            self->try_create_pair();
        
}

uint32_t GrayServer::generate_otp() {
    static thread_local std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<uint32_t> dist(100000, 999999);
    return dist(rng);
}

void GrayServer::check_data_pool() {
    auto self = shared_from_this();
    if (!self->alive) return;

    bool expected = false;
    if (!check_in_progress.compare_exchange_strong(expected, true))
        return;

    {
        std::lock_guard<std::mutex> lock(data_pool_mutex);

        auto it = data_pool.begin();
        while (it != data_pool.end()) {
            if (!(*it)->is_open()) {
                it = data_pool.erase(it);
            }
            else {
                ++it;
            }
        }
    }

    if (data_pool.size() < pool_size) {
        current_otp = generate_otp();

        if (!control_socket || !control_socket->lowest_layer().is_open()) {
            check_in_progress = false;
            return;
        }
        {
            std::lock_guard<std::mutex> lock(otp_pool_mutex);
            otp_pool.push_back(current_otp);
        }
		
        send_control_packet(2, current_otp, [self](const asio::error_code& ec) {
            if (ec) {
                
                spdlog::error("Server {}: failed to send OTP control packet (code {}): {}", self->id, ec.value(), ec.message());
            }
            
            self->check_in_progress = false;
            });
    }
    else {
        check_in_progress = false;
    }

    data_pool_timer.expires_after(std::chrono::seconds(1));
    data_pool_timer.async_wait([self](const asio::error_code& ec) {
        if (!self->alive || ec == asio::error::operation_aborted) return;
        self->check_data_pool();
        });
}

void GrayServer::enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock)
{
    asio::error_code ec;
    sock->set_option(asio::socket_base::keep_alive(true), ec);
    if (ec) {
        spdlog::error("Server {}: set_option keep_alive failed (code {}): {}", id, ec.value(), ec.message());
        return;
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

void GrayServer::shutdown()
{
    auto self = shared_from_this();

    asio::post(io_context_, [self]() {
        bool expected = true;
        if (!self->alive.compare_exchange_strong(expected, false))
            return;

        self->ping_timer.cancel();
        self->pong_timer.cancel();
        self->data_pool_timer.cancel();
		self->speed_monitor_timer.cancel();

        asio::error_code ec;

        if (self->client_acceptor_ && self->client_acceptor_->is_open())
            self->client_acceptor_->close(ec);

        if (self->control_socket &&
            self->control_socket->lowest_layer().is_open())
        {
            self->control_socket->lowest_layer().shutdown(
                asio::ip::tcp::socket::shutdown_both, ec);
            self->control_socket->lowest_layer().close(ec);
        }

        self->remove_all_pairs();

        {
            std::lock_guard<std::mutex> lock(self->data_pool_mutex);
            for (auto& sock : self->data_pool) {
                if (sock && sock->is_open())
                    sock->close(ec);
            }
            self->data_pool.clear();
        }

        {
            std::lock_guard<std::mutex> lock(self->client_pool_mutex);
            for (auto& sock : self->client_pool) {
                if (sock && sock->is_open())
                    sock->close(ec);
            }
            self->client_pool.clear();
        }

        if (auto mgr = self->manager_.lock()) {
            mgr->remove(self->id);
        }

        });
}

void GrayServer::send_ping() {
    auto self = shared_from_this();
    if (!self->alive || !control_socket || !control_socket->lowest_layer().is_open())
        return;

    // If we're already waiting for a pong, don't send another ping
    bool expected = false;
    if (!self->waiting_for_pong.compare_exchange_strong(expected, true)) {
        spdlog::warn("Server {}: send_ping skipped because a pong is already awaited", self->id);
        return; 
    }

    send_control_packet(1, 0, [self](const asio::error_code& ec) {
        if (ec) {
            spdlog::error("Server {}: send_ping failed (code {}): {}", self->id, ec.value(), ec.message());
            self->waiting_for_pong = false;
            self->shutdown();
            return;
        }
        self->last_ping_start_ = Clock::now();
       
        // Start waiting for pong (async read + timeout)
        self->wait_pong();
        });
}

void GrayServer::wait_pong() {
    auto self = shared_from_this();
    if (!self->alive || !self->control_socket || !self->control_socket->lowest_layer().is_open())
        return;

    
    self->pong_timer.cancel();  
    self->pong_timer.expires_after(std::chrono::seconds(self->ping_timeout_sec));
    self->pong_timer.async_wait([self](const asio::error_code& ec) {
        if (ec == asio::error::operation_aborted) return;
        if (!self->alive) return;

        spdlog::error("Server {}: pong timeout, closing control socket", self->id);
        asio::error_code ignored;
        self->control_socket->lowest_layer().close(ignored);
        
        self->waiting_for_pong = false;
        });

   
    asio::async_read(*self->control_socket, asio::buffer(self->pong_buf),
        [self](const asio::error_code& ec, std::size_t bytes_transferred) {

            if (!self->alive) {
                self->waiting_for_pong = false;
                return;
            }

            if (ec) {
                if (ec == asio::error::eof || bytes_transferred == 0) {
                    spdlog::warn("Server {}: received 0 bytes or connection closed", self->id);
                }
                else {
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
            uint32_t pkt_type = ntohl(pkt.type);

            
          

            auto elapsed = Clock::now() - self->last_ping_start_;
            self->last_ping_ms_ = std::chrono::duration_cast<std::chrono::milliseconds>(elapsed);
            self->last_ping_ms = static_cast<uint32_t>(self->last_ping_ms_.count());

            
            self->waiting_for_pong = false;
            self->pong_timer.cancel();
            self->schedule_ping();
        }
    );
}

void GrayServer::schedule_ping() {
    auto self = shared_from_this();
    self->ping_timer.cancel();
    self->ping_timer.expires_after(std::chrono::seconds(ping_interval_sec));
    self->ping_timer.async_wait([self](const asio::error_code& ec) {
        if (!self->alive || ec == asio::error::operation_aborted) return;
        self->send_ping();
        });
}

void GrayServer::async_accept_client() {
    auto self = shared_from_this();
    if (!self->alive) return;

    auto sock = std::make_shared<asio::ip::tcp::socket>(io_context_);

    client_acceptor_->async_accept(*sock,
        [self, sock](const asio::error_code& ec)
        {
            if (!self->alive) return;
            if (!self->client_acceptor_ || !self->client_acceptor_->is_open()) return;

            if (!ec)
            {
                {
                    std::lock_guard<std::mutex> lock(self->client_pool_mutex);
                    self->client_pool.push_back(sock);
                }
                self->try_create_pair();
            }

            self->async_accept_client();
        });
}

std::string GrayServer::generate_id(std::shared_ptr<asio::ip::tcp::socket> sock) {
    auto endpoint = sock->remote_endpoint();
    auto ip = endpoint.address().to_string();
    auto port = std::to_string(endpoint.port());


    std::string id_str = ip + ":" + port;

    return id_str;
}

void GrayServer::try_create_pair() {
    std::shared_ptr<asio::ip::tcp::socket> client_sock;
    std::shared_ptr<asio::ip::tcp::socket> data_sock;

    {
        std::lock_guard<std::mutex> lock_client(client_pool_mutex);
        std::lock_guard<std::mutex> lock_data(data_pool_mutex);

        if (client_pool.empty() || data_pool.empty()) return;

        client_sock = client_pool.back();
        client_pool.pop_back();

        auto it = std::find_if(data_pool.begin(), data_pool.end(),
            [](const auto& sock) { return sock->is_open(); });

        if (it == data_pool.end()) {
            client_pool.push_back(client_sock);
            return;
        }

        data_sock = *it;
        data_pool.erase(it);
    }

    auto pair = std::make_shared<link_par>();
    pair->client_socket = client_sock;
    pair->data_socket = data_sock;
    pair->pair_id = generate_id(client_sock);
    pair->done_count = 2;
    pair->trafic_in = 0;
    pair->trafic_out = 0;

    {
        std::lock_guard<std::mutex> lock(link_pool_mutex);
        link_pool.push_back(pair);
    }

    splice_loop(client_sock, data_sock, pair, "in");
    splice_loop(data_sock, client_sock, pair, "out");
}

void GrayServer::splice_loop(
    std::shared_ptr<asio::ip::tcp::socket> in_sock,
    std::shared_ptr<asio::ip::tcp::socket> out_sock,
    std::shared_ptr<link_par> pair,
    std::string way)
{
    auto self = shared_from_this();
    auto buffer = std::make_shared<std::array<char, 4096>>();

    in_sock->async_read_some(
        asio::buffer(*buffer),
        [self, in_sock, out_sock, buffer, pair,way]
        (const asio::error_code& ec, std::size_t bytes)
        {
            if (ec) {
                if (ec != asio::error::eof &&
                    ec != asio::error::operation_aborted) {
                    spdlog::error("Pair {}: read error (code {}): {}", pair->pair_id, ec.value(), ec.message());
                }
                self->remove_pair(pair->pair_id);
                return;
            }

            if (bytes == 0) {
                self->remove_pair(pair->pair_id);
                return;
            }
            if (way == "in") {
                pair->trafic_in += bytes; 
                // spdlog::debug("Pair {}: total in: {}", pair->pair_id, pair->trafic_in.load());
            }
            else {
                pair->trafic_out += bytes;
                // spdlog::debug("Pair {}: total out: {}", pair->pair_id, pair->trafic_out.load());
            }

            asio::async_write(
                *out_sock,
                asio::buffer(buffer->data(), bytes),
                [self, in_sock, out_sock, buffer, pair,way]
                (const asio::error_code& ec_write, std::size_t written)
                {
                    if (ec_write) {
                        if (ec_write != asio::error::eof && ec_write != asio::error::operation_aborted) {
                            spdlog::error("Pair {}: write error (code {}): {}", pair->pair_id, ec_write.value(), ec_write.message());
                        }
                        self->remove_pair(pair->pair_id);
                        return;
                    }

                    self->splice_loop(in_sock, out_sock, pair,way);
                });
        });
}

void GrayServer::remove_pair(std::string pair_id) {

    std::shared_ptr<asio::ip::tcp::socket> client_sock;
    std::shared_ptr<asio::ip::tcp::socket> data_sock;
    {
        std::lock_guard<std::mutex> lock(link_pool_mutex);

        auto it = std::find_if(link_pool.begin(), link_pool.end(),
            [&pair_id](const std::shared_ptr<link_par>& ptr) {
                return ptr && ptr->pair_id == pair_id;
            });

        if (it == link_pool.end()) return;

        client_sock = (*it)->client_socket;
        data_sock = (*it)->data_socket;

        link_pool.erase(it);
    }

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
    while (true) {
        std::string target_id;
        
        {
            std::lock_guard<std::mutex> lock(link_pool_mutex);
            if (link_pool.empty()) {
                break; 
            }

            target_id = link_pool.back()->pair_id;
        }

        remove_pair(target_id);
    }

    spdlog::info("Server {}: all pairs have been removed", id);
}

void GrayServer::send_control_packet(uint32_t type, uint32_t value, std::function<void(const asio::error_code&)> handler) {
    if (!alive || !control_socket || !control_socket->lowest_layer().is_open()) {
		spdlog::error("Server {}: send_control_packet failed: control socket is not available", id);
        return;
    }
    auto pkt = std::make_shared<Packet>();
    pkt->type = htonl(type);
    pkt->value = htonl(value);
	
    asio::async_write(*control_socket,
        asio::buffer(pkt.get(), sizeof(Packet)),
        [self = shared_from_this(), pkt, handler](const asio::error_code& ec, std::size_t) {
            
            if (ec) {
                spdlog::error("Server {}: send_control_packet failed (code {}): {}", self->id, ec.value(), ec.message());
                self->shutdown();
            }
            if (handler) handler(ec);
        });
}

void GrayServer::start_speed_monitor() {
    auto self = shared_from_this();

    if (!self->alive) return;

    if (self->speed_monitor_running.exchange(true)) {
        return;
    }

    self->last_measure_time = std::chrono::steady_clock::now();
    self->schedule_speed_monitor();
}

void GrayServer::schedule_speed_monitor() {
    auto self = shared_from_this();

    self->speed_monitor_timer.expires_at(
        std::chrono::steady_clock::now() + std::chrono::seconds(1));

    self->speed_monitor_timer.async_wait([self](const asio::error_code& ec) {
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

        {
            std::lock_guard<std::mutex> lock(self->link_pool_mutex);

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
        }

        double speed_in = total_bytes_in / seconds;
        double speed_out = total_bytes_out / seconds;

        constexpr double BYTES_TO_MB = 1.0 / (1000.0 * 1000.0);

        if (speed_in > 0 || speed_out > 0) {
            spdlog::info(
                "Server Speed: In: {:.2f} MB/s, Out: {:.2f} MB/s | Active pairs: {}",
                speed_in * BYTES_TO_MB,
                speed_out * BYTES_TO_MB,
                self->link_pool.size());
        }

        self->total_speed_in.store((uint64_t)speed_in, std::memory_order_relaxed);
        self->total_speed_out.store((uint64_t)speed_out, std::memory_order_relaxed);
		self->total_traffic_session += total_bytes_in + total_bytes_out;
        self->schedule_speed_monitor();
        });
}