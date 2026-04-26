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
#include <openssl/rand.h>
#include <stdexcept>
#include <filesystem>
// Data structure for server information + functions to convert to/from string for file storage
struct Server_struct {
    uint32_t id=0;
    int client_port=0;
    std::string comment="0";
	uint64_t total_traffic = 0;
	uint64_t this_session_traffic = 0;
    std::string certificate = "";
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
    std::filesystem::path configs_dir = "Gray_servers config";

    void ensure_file();
    bool write_server_config_file(const Server_struct& entry, int control_port, const std::string& server_ip, const std::string& private_key);
    std::filesystem::path get_server_config_path(uint32_t id) const;
    void read_id();
    void read_ports();
    int gen_id();
    bool is_port_available(int port);
public:
    ~DataServers() {
        for (const auto& s : servers_id) {
            calculate_total_traffic(s.id);
        }
        save_all();
        spdlog::info("DataServers destroyed. Final save completed.");
    }
    DataServers();
    bool add_id(const std::string comment_, int control_port, const std::string& server_ip);
    bool deleteServerById(uint32_t id);
	bool updateServerComment(uint32_t id, const std::string& new_comment);
    void save_all();
    bool updateServerTraffic(uint32_t id, uint64_t this_session_traffic);
    void calculate_total_traffic(uint32_t id);

    bool authorize_id(uint32_t id, const std::string& certificate_pem = "") const;
    int get_ports_by_id(uint32_t search_id) const;
    std::vector<Server_struct>  get_servers();
	bool add_ports(int first, int second = 0);
    bool delete_port(int first, int second = 0);
	std::string get_port_pool() const;
	uint64_t get_total_traffic_by_id(uint32_t id) const;
    bool read_server_config_file(uint32_t id, std::string& content) const;
};

uint32_t get_random(unsigned int min, unsigned int max);
