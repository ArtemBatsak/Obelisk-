#pragma once
#include "manager/Server_manager.h"
#include <asio.hpp>
#include <asio/ts/internet.hpp>
#include <asio/ts/buffer.hpp>
#include <asio/ts/io_context.hpp>
#include <asio/steady_timer.hpp>
#include <asio/ssl.hpp>
#include <memory>
#include <vector>
#include <array>
#include <atomic>
#include <thread>
#include <algorithm>
#include <cstdint>
#include <functional>
#include <chrono>
#include <optional>
#include <string>
#ifdef _WIN32
#include <winsock2.h>
#include <mstcpip.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#endif

class ServerManager;

using ssl_socket = asio::ssl::stream<asio::ip::tcp::socket>;

struct Packet {
    uint32_t type;
    uint32_t value;
};

struct link_par {
    std::shared_ptr<asio::ip::tcp::socket> data_socket;
    std::shared_ptr<asio::ip::tcp::socket> client_socket;
    std::string pair_id;
    std::atomic<uint64_t> trafic_in{ 0 };
    std::atomic<uint64_t> trafic_out{ 0 };
    uint64_t last_in_snapshot{ 0 };
    uint64_t last_out_snapshot{ 0 };
};

struct OtpEntry {
    uint32_t value;
    std::chrono::steady_clock::time_point expires_at;
};

struct PendingSocket {
    std::shared_ptr<asio::ip::tcp::socket> sock;
    std::chrono::steady_clock::time_point accepted_at;
};

class GrayServer : public std::enable_shared_from_this<GrayServer> {
    int id;
    int client_port;
    int data_port;
    int pool_size;
    int max_pending_clients;

    bool alive = true;
    asio::any_io_executor io_context_;
    asio::strand<asio::any_io_executor> strand_{asio::make_strand(io_context_)};
    using Clock = std::chrono::steady_clock;

    std::shared_ptr<asio::ip::tcp::acceptor> client_acceptor_;
    std::vector<PendingSocket> client_pool;

    void init_acceptor(int client_port);
    void async_accept_client();

    std::vector<PendingSocket> data_pool;
    asio::steady_timer data_pool_timer;

    std::vector<OtpEntry> otp_pool;
    bool check_in_progress = false;

    uint32_t current_otp;
    std::optional<asio::ip::address> allowed_data_ip_;

    static constexpr std::chrono::seconds otp_ttl_{30};
    static constexpr std::chrono::seconds pending_idle_timeout_{60};
    static constexpr int max_pool_size_ = 64;

    uint32_t generate_otp();
    void check_data_pool();
    void purge_expired_otps();
    void purge_idle_pending();
    std::size_t otp_pool_cap() const;

    std::vector<std::shared_ptr<link_par>> link_pool;
    std::atomic<uint32_t> active_pairs_count_{ 0 };

    void try_create_pair();
    void remove_pair(const std::string& pair_id);
    void remove_all_pairs();

    void splice_loop(
        std::shared_ptr<asio::ip::tcp::socket> in_sock,
        std::shared_ptr<asio::ip::tcp::socket> out_sock,
        std::shared_ptr<link_par> pair,
        bool way
    );

    std::string generate_id(std::shared_ptr<asio::ip::tcp::socket> sock);

    std::shared_ptr<ssl_socket> control_socket;
    std::weak_ptr<ServerManager> manager_;

    asio::steady_timer ping_timer;
    asio::steady_timer pong_timer;

    std::array<char, sizeof(Packet)> pong_buf{};
    std::size_t pong_bytes = 0;

    bool waiting_for_pong = false;
    Clock::time_point last_ping_start_;
    std::chrono::milliseconds last_ping_ms_{ 0 };
    std::atomic<uint32_t> last_ping_ms{ 0 };

    int ping_interval_sec;
    int ping_timeout_sec;

    void send_ping();
    void wait_pong();
    void schedule_ping();
    void send_control_packet(uint32_t type, uint32_t value,
        std::function<void(const asio::error_code&)> handler = nullptr);

    asio::steady_timer speed_monitor_timer;

    std::atomic<uint64_t> total_speed_in{ 0 };
    std::atomic<uint64_t> total_speed_out{ 0 };
    std::atomic<uint64_t> total_traffic_session{ 0 };

    bool speed_monitor_running = false;
    std::chrono::steady_clock::time_point last_measure_time;

    void schedule_speed_monitor();
    void start_speed_monitor();

    static constexpr std::size_t BuffSize = 64 * 1024;

    void enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock);

public:
    GrayServer(int server_id,
        std::shared_ptr<ssl_socket> control_sock,
        asio::any_io_executor io,
        int client_port,
        int data_port,
        int pool_size,
        int max_pending_clients,
        std::shared_ptr<ServerManager> manager)
        : id(server_id),
        control_socket(control_sock),
        io_context_(io),
        data_port(data_port),
        client_port(client_port),
        pool_size(std::clamp(pool_size, 1, max_pool_size_)),
        max_pending_clients(std::max(1, max_pending_clients)),
        manager_(manager),
        ping_interval_sec(5),
        ping_timeout_sec(3),
        ping_timer(io),
        pong_timer(io),
        data_pool_timer(io),
        speed_monitor_timer(io),
        current_otp(0)
    {
        if (control_socket) {
            asio::error_code ec;
            auto ep = control_socket->lowest_layer().remote_endpoint(ec);
            if (!ec) {
                allowed_data_ip_ = ep.address();
            }
        }
    }

    void start();

    void handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t otp);
    uint32_t get_id() const { return id; }
    uint32_t get_ping() const { return last_ping_ms.load(); }
    uint32_t get_active_pairs() {
        return active_pairs_count_.load(std::memory_order_acquire);
    }
    uint64_t get_total_traffic() const { return total_traffic_session.load(); }
    uint64_t get_total_speed_in() const { return total_speed_in.load(); }
    uint64_t get_total_speed_out() const { return total_speed_out.load(); }

    void shutdown();
};
