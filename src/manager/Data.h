#pragma once
// Data.h
// Brief: Utilities for storing server metadata and managing configured GrayServer instances.
// - Server_struct: holds id, client/data ports and a comment; supports simple serialization.
// - DataServers: manages list of known servers and available ports (file-backed).
// - ServerManager: keeps active GrayServer instances and provides shutdown/remove operations.

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

struct Server_struct {
    int id;
    int client_port;
    int data_port;
    std::string comment;

    std::string to_string() const;
    static Server_struct from_string(const std::string& line);
};

class GrayServer; // forward

class DataServers {
private:
    mutable std::mutex mtx_;
    std::vector<Server_struct> servers_id;
    std::string id_file = "Servers.txt";
    std::vector<int> ports;
    std::string port_file = "Port.txt";

    void ensure_file();
    void read_id();
    void read_ports();
    int gen_id();

public:
    DataServers();

    bool add_id(const std::string comment_);
    void show_id() const;
    void delete_id();
    void save_all();


    bool deleteServerById(uint32_t id);
	bool updateServerComment(uint32_t id, const std::string& new_comment);

    bool authorize_id(uint32_t id) const;
    std::array<int, 2> get_ports_by_id(int search_id) const;
    std::vector<Server_struct>  get_servers();

};

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

