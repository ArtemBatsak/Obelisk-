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
    uint64_t pair_id;
    int done_count = 2;
};

// The GrayServer class represents a single proxy server instance. It manages incoming client and data connections, 
// maintains a pool of OTPs for authentication, handles ping/pong for health checks, and manages active client-data pairs. 
// It communicates with the ServerManager for coordination and control.

// HOW IT WORKS: We accept the control socket along with its ID, pool_size, etc.
// We then check the specified pool_size and send connection requests to the data port.
// We ensure that only the necessary sockets are added to the pool using an OTP key.

class GrayServer : public std::enable_shared_from_this<GrayServer> {
private:
    int id;
    int client_port;
    int data_port;
    uint32_t current_otp;
    int pool_size;
	std::vector<uint32_t> otp_pool;
    std::mutex otp_pool_mutex;
    std::atomic<bool> check_in_progress{ false };
    std::atomic<bool> alive{ true };
    std::shared_ptr<asio::ip::tcp::acceptor> data_acceptor_;
    std::shared_ptr<asio::ip::tcp::acceptor> client_acceptor_;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> data_pool;
    std::vector<std::shared_ptr<asio::ip::tcp::socket>> client_pool;

    asio::steady_timer ping_timer;
	asio::steady_timer pong_timer;
	asio::steady_timer data_pool_timer;

    using Clock = std::chrono::steady_clock;

    Clock::time_point last_ping_start_;          
    std::chrono::milliseconds last_ping_ms_{ 0 };
    std::atomic<uint32_t> last_ping_ms{ 0 };

    int ping_interval_sec;
    int ping_timeout_sec;
    std::shared_ptr<ssl_socket> control_socket;
    std::vector<link_par> link_pool;
    std::mutex link_pool_mutex;
    std::mutex data_pool_mutex;
    std::mutex client_pool_mutex;
    asio::any_io_executor io_context_;

    static constexpr std::size_t BuffSize = 4096;
    std::array<char, sizeof(Packet)> pong_buf{};
    std::size_t pong_bytes = 0;

   
    std::atomic<bool> waiting_for_pong{ false };

    std::weak_ptr<ServerManager> manager_;

    void init_acceptor(int client_port);
    void check_data_pool();
    void enable_keepalive(std::shared_ptr<asio::ip::tcp::socket> sock);
    void async_accept_client();

    void send_ping();
    void wait_pong();
    void schedule_ping();

    uint32_t generate_otp();
    uint64_t generate_id(std::shared_ptr<asio::ip::tcp::socket> sock);

    void try_create_pair();
    void splice_loop(std::shared_ptr<asio::ip::tcp::socket> in_sock,
        std::shared_ptr<asio::ip::tcp::socket> out_sock,
        uint64_t pair_id);
    void remove_pair(uint64_t pair_id);
    void remove_all_pairs();
    
    void send_control_packet(uint32_t type, uint32_t value, std::function<void(const asio::error_code&)> handler = nullptr);
    

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
        alive(true)
    {
    }

    void start() {
        init_acceptor(client_port);
        async_accept_client();
        check_data_pool();
		schedule_ping();    
	}
    void handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock, uint32_t otp);
    uint32_t get_id() const { return id; }
    uint32_t get_ping() const { return last_ping_ms.load(); }
	uint32_t get_active_pairs() {
		std::lock_guard<std::mutex> lock(link_pool_mutex);
		return static_cast<uint32_t>(link_pool.size());
	}
    void shutdown();
};



