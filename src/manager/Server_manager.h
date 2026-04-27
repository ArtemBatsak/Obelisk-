#pragma once
#include "manager/Data.h"
#include "server/Server_class.h"
#include <vector>
#include <memory>
#include <mutex>
#include <atomic>
#include <coroutine>
#include <chrono>
#include <asio.hpp>
#include <asio/ssl.hpp>
#include <string>
#include "tls/Tls_session.h"

using asio::ip::tcp;

class DataServers;
class GrayServer;

struct DATA_PACKET {
    uint32_t id;
    uint32_t otp;
    
};

class ServerManager : public std::enable_shared_from_this<ServerManager> {
public:
    ServerManager(std::shared_ptr<std::atomic<bool>> running_,
        int CONTROL_PORT_,
        int DATA_PORT_,
        std::shared_ptr<DataServers> data_servers_,
        std::string tls_cert_path_,
        std::string tls_key_path_,
        asio::any_io_executor io) :
		running(running_),
        control_port(CONTROL_PORT_),
        data_port(DATA_PORT_),
		data_servers(data_servers_),
        tls_cert_path(std::move(tls_cert_path_)),
        tls_key_path(std::move(tls_key_path_)),
        io_context_(io),
        ssl_ctx(asio::ssl::context::tls_server)
    {
    }
    ~ServerManager() {
		traffic_sync_timer.cancel();
        save_data_timer.cancel();
        if (control_acceptor && control_acceptor->is_open()) control_acceptor->close();
        if (data_acceptor && data_acceptor->is_open()) data_acceptor->close();
        shutdown_all();
	}
    
    void start() {
        start_up_tls();
        init_acceptor();
        async_accept_control();
        async_accept_data();
	}

    void start_up_tls();
    void init_acceptor();
    void schedule_traffic_sync();
    void persist_online_traffic();
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
    uint64_t get_total_traffic(uint32_t id);
    uint64_t get_total_speed_in(uint32_t id);
    uint64_t get_total_speed_out(uint32_t id);
    int get_control_port() const { return control_port; }
    std::string get_tls_certificate_pem() const;
	void save_data_to_disk();
    bool delete_server(uint32_t id);

private:
    std::shared_ptr<std::atomic<bool>> running;
    asio::any_io_executor io_context_;
    const int control_port;
	const int data_port;
    std::string tls_cert_path;
    std::string tls_key_path;
    std::string tls_certificate_pem;
    asio::ssl::context ssl_ctx;
    std::weak_ptr<DataServers> data_servers;
    std::mutex mtx_;
    std::vector<std::shared_ptr<GrayServer>> servers;
    std::shared_ptr<asio::ip::tcp::acceptor> data_acceptor;
    std::shared_ptr<asio::ip::tcp::acceptor> control_acceptor;
    std::vector<std::pair<uint32_t, uint64_t>> previous_traffic_snapshot;
    asio::steady_timer traffic_sync_timer{ io_context_ };
	asio::steady_timer save_data_timer{ io_context_ };
    std::chrono::seconds traffic_sync_interval{ 1 };
	std::chrono::seconds save_data_interval{ 600 }; // Every 10 minutes we will save data to disk
};



