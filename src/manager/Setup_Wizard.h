#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <algorithm>
#include <memory>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include "tls/Tls_session.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

// Глобальные пути (определены в другом месте)
extern std::string CONFIG_PATH;
extern std::string TLS_CERT_PATH;
extern std::string TLS_KEY_PATH;

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
    std::string tls_cert_path;
    std::string tls_key_path;
};

class ConfigManager : public std::enable_shared_from_this<ConfigManager> {
public:
    ConfigManager();
    ~ConfigManager();

    bool check_config();
    void set_up();
    Config get_config() const { return config_; }
    bool verify_password(const std::string& input_login, const std::string& input_password);

private:
    Config config_;

    bool save();
    void load();
    bool ensure_tls_material();

    HashResult get_safe_hash(const std::string& password);
    std::string generate_random_salt(size_t length);

    bool is_port_available(int port);
    void init_network();
    void cleanup_network();
};

bool is_tls_valid(const std::string& cert_path, const std::string& key_path);