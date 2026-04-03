#pragma once
#include <iostream>
#include <string>
#include <spdlog/spdlog.h>
#include <fstream>
#include <nlohmann/json.hpp>
#include <openssl/sha.h>
#include <openssl/rand.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

struct HashResult {
    std::string salt;
    std::string hash;
};

struct Config {
    int control_port;
    int data_port;
    int web_port;
    std::string admin_password_hash;
    std::string admin_username;
	std::string admin_password_salt; 
};

class ConfigManager : public std::enable_shared_from_this<ConfigManager> {
public: 
	bool check_config();
    void set_up();
	Config get_config() const { return config_; }
    bool verify_password(const std::string& input_login, const std::string& input_password);
private:
	Config config_;
    bool save();
    HashResult get_safe_hash(const std::string& password);
    bool is_port_available(int port);
    void load();
    std::string generate_random_salt(size_t length);
};
