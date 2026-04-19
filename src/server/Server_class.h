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
#include <mutex>      
#include <atomic>      
#include <thread>      
#include <random>      
#include <algorithm>   
#include <cstdint>     
#include <functional>  
#include <chrono>      
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
    int done_count = 2;
    std::atomic<uint64_t> trafic_in{ 0 };
    std::atomic<uint64_t> trafic_out{ 0 };
    uint64_t last_in_snapshot{ 0 };
    uint64_t last_out_snapshot{ 0 };

};

// The GrayServer class represents a single proxy server instance. It manages incoming client and data connections, 
// maintains a pool of OTPs for authentication, handles ping/pong for health checks, and manages active client-data pairs. 
// It communicates with the ServerManager for coordination and control.

// HOW IT WORKS: We accept the control socket along with its ID, pool_size, etc.
// We then check the specified pool_size and send connection requests to the data port.
// We ensure that only the necessary sockets are added to the pool using an OTP key.

class GrayServer : public std::enable_shared_from_this<GrayServer> {
    // ===================== CORE =====================
    int id;
    int client_port;
    int data_port;
    int pool_size;

    std::atomic<bool> alive{ true };
    asio::any_io_executor io_context_;
    using Clock = std::chrono::steady_clock;

    // ============ CLIENT CONNECTIONS ============
    std::shared_ptr<asio::ip::tcp::acceptor> client_acceptor_;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> client_pool;
    std::mutex client_pool_mutex;

    void init_acceptor(int client_port);
    void async_accept_client();

    // ============ DATA POOL / OTP ============
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> data_pool;
    std::mutex data_pool_mutex;
    asio::steady_timer data_pool_timer;

    std::vector<uint32_t> otp_pool;
    std::mutex otp_pool_mutex;
    std::atomic<bool> check_in_progress{ false };

    uint32_t current_otp;

    uint32_t generate_otp();
    void check_data_pool();

    // ============ LINK PAIRS ============

    std::vector<std::shared_ptr<link_par>> link_pool;
    std::mutex link_pool_mutex;

    void try_create_pair();
    void remove_pair(std::string pair_id);
    void remove_all_pairs();

    void splice_loop(
        std::shared_ptr<asio::ip::tcp::socket> in_sock,
        std::shared_ptr<asio::ip::tcp::socket> out_sock,
        std::shared_ptr<link_par> pair,
        std::string way
    );

    std::string generate_id(std::shared_ptr<asio::ip::tcp::socket> sock);

    // ============ CONTROL PLANE ============
    std::shared_ptr<ssl_socket> control_socket;
    std::weak_ptr<ServerManager> manager_;

    asio::steady_timer ping_timer;
    asio::steady_timer pong_timer;

    std::array<char, sizeof(Packet)> pong_buf{};
    std::size_t pong_bytes = 0;

    std::atomic<bool> waiting_for_pong{ false };
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

    // ============ METRICS ============
    asio::steady_timer speed_monitor_timer;

    std::atomic<uint64_t> total_speed_in{ 0 };
    std::atomic<uint64_t> total_speed_out{ 0 };
    std::atomic<uint64_t> total_traffic_session{ 0 };

    std::atomic<bool> speed_monitor_running{ false };
    std::chrono::steady_clock::time_point last_measure_time;

    void schedule_speed_monitor();
    void start_speed_monitor();

    // ============ HELPERS ============
    static constexpr std::size_t BuffSize = 256 * 1024;

    void enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock);

public:
    GrayServer(int server_id,
        std::shared_ptr<ssl_socket> control_sock,
        asio::any_io_executor io,
        int client_port,
        int data_port,
        int pool_size,
        std::shared_ptr<ServerManager> manager) 
        : id(server_id),
        control_socket(control_sock),
        io_context_(io),
        data_port(data_port),
        client_port(client_port),
        pool_size(pool_size),
        manager_(manager),
        ping_interval_sec(5),
        ping_timeout_sec(3),
        ping_timer(io),
        pong_timer(io),
        data_pool_timer(io),
		speed_monitor_timer(io),
        alive(true),
		current_otp(0)
    {
    }

    void start() {
        init_acceptor(client_port);
        async_accept_client();
        check_data_pool();
		schedule_ping();
        start_speed_monitor();
	}

    void handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t otp);
    uint32_t get_id() const { return id; }
    uint32_t get_ping() const { return last_ping_ms.load(); }
	uint32_t get_active_pairs() {
		std::lock_guard<std::mutex> lock(link_pool_mutex);
		return static_cast<uint32_t>(link_pool.size());
	}
	uint64_t get_total_traffic() const { return total_traffic_session.load(); }
    uint64_t get_total_speed_in() const { return total_speed_in.load(); }
    uint64_t get_total_speed_out() const { return total_speed_out.load(); }

    void shutdown();
};



