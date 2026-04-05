#pragma once
#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <memory>
#include <mutex>
#include <algorithm>
#include <iostream>
#include <spdlog/spdlog.h>
#include <fstream>
#include <set>
#include "asio.hpp"
#include <nlohmann/json.hpp>
// Data structure for server information + functions to convert to/from string for file storage
struct Server_struct {
    int id=0;
    int client_port=0;
    std::string comment="0";

    std::string to_string() const;
    static Server_struct from_string(const std::string& line);
};

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
    void save_all();
    bool is_port_available(int port);
public:
	
    DataServers();
    bool add_id(const std::string comment_);
    bool deleteServerById(uint32_t id);
	bool updateServerComment(uint32_t id, const std::string& new_comment);

    bool authorize_id(uint32_t id) const;
    int get_ports_by_id(int search_id) const;
    std::vector<Server_struct>  get_servers();
	bool add_ports(int first, int second = 0);
    bool delete_port(int first, int second = 0);
	std::string get_port_pool() const;

};
