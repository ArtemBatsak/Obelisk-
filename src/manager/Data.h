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
#include "path/Path.h"

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
    std::set<int> ports;
    void ensure_file();
    bool write_server_config_file(const Server_struct& entry, int control_port, const std::string& server_ip, const std::string& private_key, const std::string& trusted_server_certificate); std::filesystem::path get_server_config_path(uint32_t id) const;
    void read_id();
    void read_ports();
    int gen_id();
    bool is_port_available(int port);
public:
    ~DataServers() {
        {
            std::lock_guard<std::mutex> lock(mtx_);
            for (auto& s : servers_id) {
                s.total_traffic += s.this_session_traffic;
                s.this_session_traffic = 0;
            }
            // save_all без блокировки — мы уже держим mtx_
            std::ofstream outfile_id(Path::DataServersFilePath().string(), std::ios::trunc);
            if (outfile_id.is_open()) {
                for (const auto& entry : servers_id) {
                    outfile_id << entry.to_string() << "\n";
                }
            }
            std::ofstream outfile_port(Path::DataPortsFilePath().string(), std::ios::trunc);
            if (outfile_port.is_open()) {
                for (int port : ports) {
                    outfile_port << port << "\n";
                }
            }
        }
        spdlog::info("DataServers destroyed. Final save completed.");
    }
    DataServers();
    bool add_id(const std::string comment_, int control_port, const std::string& server_ip, const std::string& trusted_server_certificate ="");
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
