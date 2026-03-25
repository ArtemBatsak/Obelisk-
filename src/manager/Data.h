#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <algorithm>
#include "server/Server_class.h"
#include <iostream>
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <fstream>
#include <set>

// Data structure for server information + functions to convert to/from string for file storage
struct Server_struct {
    int id;
    int client_port;
    int data_port;
    std::string comment;

    std::string to_string() const;
    static Server_struct from_string(const std::string& line);
};

class GrayServer; // forward
// Data for all servers, handles file I/O and ID generation, also provides thread-safe access to server data for the web interface
class DataServers {
private:
    mutable std::mutex mtx_;
    std::vector<Server_struct> servers_id;
    std::string id_file = "Servers.txt";
    std::set<int> ports;
    std::string port_file = "Port.txt";

    void ensure_file();
    void read_id();
    void read_ports();
    int gen_id();

public:
    DataServers();

    bool add_id(const std::string comment_);
    void show_id() const;
    void save_all();


    bool deleteServerById(uint32_t id);
	bool updateServerComment(uint32_t id, const std::string& new_comment);

    bool authorize_id(uint32_t id) const;
    std::array<int, 2> get_ports_by_id(int search_id) const;
    std::vector<Server_struct>  get_servers();
	bool add_ports(int first, int second = 0);

};
// Manager for ACTIVE servers, provides thread-safe access to server instances and operations like shutdown, ping retrieval, etc.
class ServerManager : public std::enable_shared_from_this<ServerManager> {
public:
    void add(std::shared_ptr<GrayServer> server);
    void remove(uint32_t id);
    void shutdown_all();
    bool shutdown_id(uint32_t id);
	bool server_online(uint32_t id);
	uint32_t get_ping(uint32_t id);
	uint32_t get_active_pairs(uint32_t id);
		

private:
    std::mutex mtx_;
    std::vector<std::shared_ptr<GrayServer>> servers_;
};

