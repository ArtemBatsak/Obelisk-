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
    int max_pending_clients = 100;
    std::string admin_password_hash;
    std::string admin_username;
    std::string admin_password_salt;
    std::string tls_cert_path;
    std::string tls_key_path;

    // --- Kenny multiplay: node & service API ---
    std::string node_id = "obelisk-1";          // идентификатор узла (мониторинг/будущие ноды)
    std::string web_bind = "127.0.0.1";         // на чём слушать web (приватно)
    std::string service_api_key;                // секрет для машина-машина (/api/service/*)
    std::string allow_api_peers;                // CSV IP, с кого разрешён /api/service/* (пусто = любой с ключом)
    int max_sessions = 500;                     // лимит одновременных сессий (защита от исчерпания)
    int port_pool_start = 0;                    // авто-заливка пула портов
    int port_pool_end = 0;                      // авто-заливка пула портов
    int data_pool_max = 64;                     // потолок data-пула Phantom (ожидающие клиента сокеты, макс.64)
    std::string public_ip;                      // явный внешний IP узла (пусто = определять автоматически)
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
    void apply_env();
    bool ensure_tls_material();

    HashResult get_safe_hash(const std::string& password);
    std::string generate_random_salt(size_t length);

    bool is_port_available(int port);
    void init_network();
    void cleanup_network();
};

bool is_tls_valid(const std::string& cert_path, const std::string& key_path);
