#pragma once
#include "manager/Data.h"


#include <asio.hpp>                // Основной ASIO (асинхронные сокеты, таймеры)
#include <asio/ts/internet.hpp>    // TCP-сокеты и endpoint
#include <asio/ts/buffer.hpp>      // Буферы для async_read/write
#include <asio/ts/io_context.hpp>  // io_context
#include <asio/steady_timer.hpp>

#include <memory>      // std::shared_ptr, std::make_shared
#include <vector>      // std::vector
#include <array>       // std::array
#include <mutex>       // std::mutex, std::lock_guard
#include <atomic>      // std::atomic
#include <thread>      // std::thread, thread_local
#include <random>      // std::mt19937, std::random_device, std::uniform_int_distribution
#include <algorithm>   // std::find_if, std::remove
#include <cstdint>     // uint32_t, uint64_t
#include <functional>  // std::function
#include <chrono>      // std::chrono::seconds

#ifdef _WIN32
#include <winsock2.h>  // WSAIoctl, tcp_keepalive
#include <mstcpip.h>   // SIO_KEEPALIVE_VALS
#else
#include <unistd.h>    // close
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT
#include <arpa/inet.h> // ntohl, htonl
#endif


#include <asio/ssl.hpp>


// Server_class.h
// Brief: Defines GrayServer which manages control connection to a remote "gray" server,
// accepts client and data socket connections, pairs them and forwards traffic between them.
// Also contains supportive Packet and link_par structures.

class ServerManager; // forward

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

    
    int ping_interval_sec;
    int ping_timeout_sec;
    std::shared_ptr<ssl_socket> control_socket;
    std::vector<link_par> link_pool;
    std::mutex link_pool_mutex;
    std::mutex data_pool_mutex;
    std::mutex client_pool_mutex;
    asio::io_context& io_context_;
    static constexpr std::size_t BuffSize = 4096;
    std::array<char, 4> pong_buf{};
    std::size_t pong_bytes = 0;

    std::weak_ptr<ServerManager> manager_;

    void init_acceptor(int data_port, int client_port);
    void async_accept_data();
    void handle_new_data(std::shared_ptr<asio::ip::tcp::socket> sock);
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
        asio::io_context& io,
        int data_port,
        int client_port,
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
        init_acceptor(data_port, client_port);
        async_accept_data();
        async_accept_client();
        check_data_pool();
		schedule_ping();    
	}
    uint32_t get_id() const { return id; }
    void shutdown();
};