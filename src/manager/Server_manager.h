#pragma once
#include "manager/Data.h"
#include "server/Server_class.h"
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <coroutine>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include "tls/tls_session.h"

using asio::ip::tcp;

class DataServers;
class GrayServer;

struct DATA_PACKET {
    uint32_t id;
    uint32_t otp;
    
};

class ServerManager : public std::enable_shared_from_this<ServerManager> {
public:
    ServerManager(const std::atomic<bool>& running_,
        int CONTROL_PORT_,
        int DATA_PORT_,
        std::shared_ptr<DataServers> data_servers_,
        asio::any_io_executor io) :
		running(running_),
        control_port(CONTROL_PORT_),
        data_port(DATA_PORT_),
		data_servers(data_servers_),
        io_context_(io),
        ssl_ctx(asio::ssl::context::tls_server)
    {
    }





    void start() {
        start_up_tls();
        init_acceptor();
        async_accept_control();
        async_accept_data();
	}

    void start_up_tls();
    void init_acceptor();
    void async_accept_data();
    void handle_new_data(std::shared_ptr<tcp::socket> sock);
    void async_accept_control();
    asio::awaitable<void> async_authorize(std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock);


    void add(std::shared_ptr<GrayServer> server);
    void remove(uint32_t id);
    void shutdown_all();
    bool shutdown_id(uint32_t id);
    bool server_online(uint32_t id);
    uint32_t get_ping(uint32_t id);
    uint32_t get_active_pairs(uint32_t id);

private:
    const std::atomic<bool>& running;
    asio::any_io_executor io_context_;
    const int control_port;
	const int data_port;
    asio::ssl::context ssl_ctx;
    std::weak_ptr<DataServers> data_servers;
    std::mutex mtx_;
    std::vector<std::shared_ptr<GrayServer>> servers;
    std::shared_ptr<asio::ip::tcp::acceptor> data_acceptor;
    std::shared_ptr<asio::ip::tcp::acceptor> control_acceptor;
};




