#include "Setup_wizard.h"

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <cstdlib>
#include <cctype>
#include <algorithm>
#include <set>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace {

std::string env_str(const char* name)
{
    const char* v = std::getenv(name);
    return (v && v[0]) ? std::string(v) : std::string();
}

int env_int(const char* name, int def, int min, int max)
{
    std::string s = env_str(name);
    if (s.empty()) return def;
    try {
        int v = std::stoi(s);
        if (v < min) v = min;
        if (v > max) v = max;
        return v;
    }
    catch (...) { return def; }
}

std::string trim(const std::string& s)
{
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// Разбор CSV "a,b,c" -> set
std::set<std::string> split_csv(const std::string& s)
{
    std::set<std::string> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, ',')) {
        part = trim(part);
        if (!part.empty()) out.insert(part);
    }
    return out;
}

// Случайный hex-токен заданной длины в байтах
std::string generate_token_hex(size_t bytes)
{
    std::vector<unsigned char> buf(bytes);
    if (RAND_bytes(buf.data(), static_cast<int>(bytes)) != 1) {
        spdlog::error("RAND_bytes failed while generating token");
        return std::string(bytes * 2, '0');
    }
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (auto b : buf) ss << std::setw(2) << static_cast<int>(b);
    return ss.str();
}

} // namespace

ConfigManager::ConfigManager()
{
    init_network();
    try {
        std::filesystem::path p(CONFIG_PATH);
        if (p.has_parent_path()) {
            std::filesystem::path dir = p.parent_path();
            if (!std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
                spdlog::info("Created configuration directory: {}", dir.string());
            }
        }
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to create config directory: {}", e.what());
    }
}

ConfigManager::~ConfigManager() {
    cleanup_network();
}

void ConfigManager::init_network() {
#ifdef _WIN32
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
#endif
}

void ConfigManager::cleanup_network() {
#ifdef _WIN32
    WSACleanup();
#endif
}

bool ConfigManager::check_config() {
    std::ifstream file(CONFIG_PATH);
    const bool has_file = file.good();

    if (has_file) {
        try {
            load(); // читает config.json
        }
        catch (...) {
            return false;
        }
    }

    // env всегда переопределяет конфиг (удобный деплой/секреты)
    apply_env();

    // Неинтерактивный bootstrap, если файла нет и хватает env
    if (!has_file) {
        if (config_.control_port <= 0 || config_.data_port <= 0 || config_.web_port <= 0) {
            spdlog::info("No config.json and not enough OBELISK_* env to bootstrap.");
            return false; // main запустит интерактивный set_up()
        }
        if (config_.admin_username.empty())
            config_.admin_username = "admin";
        if (config_.admin_password_hash.empty()) {
            const std::string pw = env_str("OBELISK_ADMIN_PASS");
            const std::string use = pw.empty() ? "change-me" : pw;
            HashResult h = get_safe_hash(use);
            config_.admin_password_hash = h.hash;
            config_.admin_password_salt = h.salt;
            if (pw.empty())
                spdlog::warn("OBELISK_ADMIN_PASS not set, using default 'change-me' (rotate it!)");
        }
        if (config_.service_api_key.empty()) {
            config_.service_api_key = generate_token_hex(24);
            spdlog::warn("OBELISK_SERVICE_API_KEY not set, generated a random one (save it!)");
        }
        config_.tls_cert_path = config_.tls_cert_path.empty() ? TLS_CERT_PATH : config_.tls_cert_path;
        config_.tls_key_path = config_.tls_key_path.empty() ? TLS_KEY_PATH : config_.tls_key_path;
        ensure_tls_material();
        save(); // персистим конфиг, чтобы дальше не зависеть от env
        spdlog::info("Bootstrapped Obelisk config from env (node_id={}, pool={}-{})",
                     config_.node_id, config_.port_pool_start, config_.port_pool_end);
    }

    if (config_.control_port <= 0 || config_.control_port > 65535) {
        spdlog::error("Invalid control_port in config.json {}", config_.control_port);
        return false;
    }
    if (config_.data_port <= 0 || config_.data_port > 65535) {
        spdlog::error("Invalid data_port in config.json {}", config_.data_port);
        return false;
    }
    if (config_.web_port <= 0 || config_.web_port > 65535) {
        spdlog::error("Invalid web_port in config.json {}", config_.web_port);
        return false;
    }
    if (config_.max_pending_clients <= 0) {
        spdlog::error("Invalid max_pending_clients in config.json {}", config_.max_pending_clients);
        return false;
    }
    if (config_.max_sessions <= 0) {
        spdlog::error("Invalid max_sessions in config.json {}", config_.max_sessions);
        return false;
    }
    if (config_.data_pool_max < 1 || config_.data_pool_max > 64) {
        spdlog::error("Invalid data_pool_max in config.json {}", config_.data_pool_max);
        return false;
    }
    if (config_.admin_username.empty()) {
        spdlog::error("admin_username cannot be empty in config.json");
        return false;
    }
    if (config_.admin_password_hash.empty() || config_.admin_password_salt.empty()) {
        spdlog::error("admin_password_hash and admin_password_salt must be set in config.json");
        return false;
    }

    if (config_.control_port == config_.data_port ||
        config_.control_port == config_.web_port ||
        config_.data_port == config_.web_port) {
        spdlog::error("All ports in config.json must be unique!");
        return false;
    }

    if (config_.port_pool_start > 0 && config_.port_pool_end >= config_.port_pool_start) {
        // диапазон корректен
    }

    if (!ensure_tls_material()) {
        return false;
    }

    return true;
}

void ConfigManager::apply_env() {
    if (!env_str("OBELISK_NODE_ID").empty()) config_.node_id = env_str("OBELISK_NODE_ID");
    config_.control_port = env_int("OBELISK_CONTROL_PORT", config_.control_port, 1, 65535);
    config_.data_port = env_int("OBELISK_DATA_PORT", config_.data_port, 1, 65535);
    config_.web_port = env_int("OBELISK_WEB_PORT", config_.web_port, 1, 65535);
    config_.max_pending_clients = env_int("OBELISK_MAX_PENDING_CLIENTS", config_.max_pending_clients, 1, 10000);
    config_.max_sessions = env_int("OBELISK_MAX_SESSIONS", config_.max_sessions, 1, 100000);
    config_.port_pool_start = env_int("OBELISK_PORT_POOL_START", config_.port_pool_start, 0, 65535);
    config_.port_pool_end = env_int("OBELISK_PORT_POOL_END", config_.port_pool_end, 0, 65535);
    config_.data_pool_max = env_int("OBELISK_DATA_POOL_MAX", config_.data_pool_max, 1, 64);

    if (!env_str("OBELISK_WEB_BIND").empty()) config_.web_bind = env_str("OBELISK_WEB_BIND");
    if (!env_str("OBELISK_PUBLIC_IP").empty()) config_.public_ip = env_str("OBELISK_PUBLIC_IP");
    if (!env_str("OBELISK_SERVICE_API_KEY").empty()) config_.service_api_key = env_str("OBELISK_SERVICE_API_KEY");
    if (!env_str("OBELISK_ALLOW_API_PEERS").empty()) config_.allow_api_peers = env_str("OBELISK_ALLOW_API_PEERS");

    // Пароль админки из env: хэшируем со стабильной солью
    if (!env_str("OBELISK_ADMIN_USER").empty()) config_.admin_username = env_str("OBELISK_ADMIN_USER");
    const std::string admin_pass = env_str("OBELISK_ADMIN_PASS");
    if (!admin_pass.empty()) {
        if (config_.admin_password_salt.empty())
            config_.admin_password_salt = generate_random_salt(16);
        HashResult h = get_safe_hash(admin_pass);
        config_.admin_password_hash = h.hash;
        config_.admin_password_salt = h.salt;
    }
}

void ConfigManager::set_up() {
    spdlog::set_pattern("%^%v%$");
    spdlog::info("------------------------------------------");
    spdlog::info("      OBELISK PROJECT INITIAL SETUP       ");
    spdlog::info("------------------------------------------");


    std::vector<int> selected_ports;

    auto ask_and_validate = [this, &selected_ports](const std::string& name, int def) -> int {
        std::string input;
        while (true) {
            spdlog::info("Enter {} [default: {}]: ", name, def);
            std::getline(std::cin, input);

            int port;
            if (input.empty()) {
                port = def;
            }
            else {
                try {
                    port = std::stoi(input);
                }
                catch (...) {
                    spdlog::error("Invalid input! Please enter a number.");
                    continue;
                }
            }

            if (port <= 0 || port > 65535) {
                spdlog::error("Port must be between 1 and 65535!");
                continue;
            }

            bool is_duplicate = std::find(selected_ports.begin(), selected_ports.end(), port) != selected_ports.end();
            if (is_duplicate) {
                spdlog::error("Port {} is already assigned to another service. Use a unique port!", port);
                continue;
            }

            if (is_port_available(port)) {
                selected_ports.push_back(port);
                return port;
            }
            else {
                spdlog::error("Port {} is currently in use by another program. Try another one.", port);
            }
        }
        };

    config_.control_port = ask_and_validate("Control Port", 44555);
    config_.data_port = ask_and_validate("Data Port", 50021);
    config_.web_port = ask_and_validate("Web Admin Port", 8000);

    spdlog::info("--- Admin Account Setup ---");
    spdlog::info("Enter Admin Username [default: admin]: ");
    std::string user_input;
    std::getline(std::cin, user_input);
    config_.admin_username = user_input.empty() ? "admin" : user_input;

    std::string pass_input;
    while (true) {
        spdlog::info("Enter Admin Password (min 6 chars): ");
        std::getline(std::cin, pass_input);

        if (pass_input.length() < 6) {
            spdlog::error("Password too short!");
            continue;
        }
        break;
    }

    HashResult hash_result = get_safe_hash(pass_input);
    config_.admin_password_hash = hash_result.hash;
    config_.admin_password_salt = hash_result.salt;
    config_.tls_cert_path = TLS_CERT_PATH;
    config_.tls_key_path = TLS_KEY_PATH;
    config_.max_pending_clients = 100;
    if (config_.node_id.empty()) config_.node_id = "obelisk-1";
    if (config_.web_bind.empty()) config_.web_bind = "127.0.0.1";
    if (config_.service_api_key.empty()) {
        config_.service_api_key = generate_token_hex(24);
        spdlog::warn("Generated service_api_key; save it: {}", config_.service_api_key);
    }
    if (config_.max_sessions <= 0) config_.max_sessions = 500;
    if (!ensure_tls_material()) {
        spdlog::error("Failed to create TLS certificate/key files.");
        return;
    }

    spdlog::info("");
    spdlog::info("Setup complete. Saving config...");

    if (save()) {
        spdlog::info("Config saved successfully.");
        spdlog::info("You can now login at https://localhost:{}", config_.web_port);
    }
    else {
        spdlog::error("Failed to save config.");
    }

    spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");
}

void ConfigManager::load() {
    std::ifstream file(CONFIG_PATH);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open config.json for reading");
    }

    nlohmann::json j;
    try {
        file >> j;

        config_.control_port = j.at("control_port").get<int>();
        config_.data_port = j.at("data_port").get<int>();
        config_.web_port = j.at("web_port").get<int>();
        config_.max_pending_clients = j.value("max_pending_clients", 100);

        config_.admin_username = j.at("admin_username").get<std::string>();
        config_.admin_password_hash = j.at("admin_password_hash").get<std::string>();
        config_.admin_password_salt = j.at("admin_password_salt").get<std::string>();

        config_.tls_cert_path = j.value("tls_cert_path", TLS_CERT_PATH);
        config_.tls_key_path = j.value("tls_key_path", TLS_KEY_PATH);

        config_.node_id = j.value("node_id", "obelisk-1");
        config_.web_bind = j.value("web_bind", "127.0.0.1");
        config_.service_api_key = j.value("service_api_key", "");
        config_.allow_api_peers = j.value("allow_api_peers", "");
        config_.max_sessions = j.value("max_sessions", 500);
        config_.port_pool_start = j.value("port_pool_start", 0);
        config_.port_pool_end = j.value("port_pool_end", 0);
        config_.data_pool_max = j.value("data_pool_max", 64);
        config_.public_ip = j.value("public_ip", "");

    }
    catch (const nlohmann::json::out_of_range& e) {
        throw std::runtime_error("Config error: missing required field -> " + std::string(e.what()));
    }
    catch (const nlohmann::json::type_error& e) {
        throw std::runtime_error("Config error: invalid data type -> " + std::string(e.what()));
    }
    catch (const std::exception& e) {
        throw std::runtime_error("Config error: " + std::string(e.what()));
    }
}

bool ConfigManager::save() {
    nlohmann::json j;
    j["control_port"] = config_.control_port;
    j["data_port"] = config_.data_port;
    j["web_port"] = config_.web_port;
    j["max_pending_clients"] = config_.max_pending_clients;
    j["admin_password_hash"] = config_.admin_password_hash;
    j["admin_username"] = config_.admin_username;
	j["admin_password_salt"] = config_.admin_password_salt;
    j["tls_cert_path"] = config_.tls_cert_path;
    j["tls_key_path"] = config_.tls_key_path;
    j["node_id"] = config_.node_id;
    j["web_bind"] = config_.web_bind;
    j["service_api_key"] = config_.service_api_key;
    j["allow_api_peers"] = config_.allow_api_peers;
    j["max_sessions"] = config_.max_sessions;
    j["port_pool_start"] = config_.port_pool_start;
    j["port_pool_end"] = config_.port_pool_end;
    j["data_pool_max"] = config_.data_pool_max;
    j["public_ip"] = config_.public_ip;
    try {
        std::ofstream file(CONFIG_PATH);
        if (!file.is_open()) return false; 
        file << j.dump(4);
        file.close();
        return file.good(); 
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to save config: {}", e.what());
        return false;
    }
}

bool ConfigManager::ensure_tls_material() {
    if (config_.tls_cert_path.empty()) config_.tls_cert_path = TLS_CERT_PATH;
    if (config_.tls_key_path.empty()) config_.tls_key_path = TLS_KEY_PATH;

    if (std::filesystem::exists(config_.tls_cert_path) &&
        std::filesystem::exists(config_.tls_key_path)) {

        if (is_tls_valid(config_.tls_cert_path, config_.tls_key_path)) {
            return true; 
        }
        else {
            spdlog::warn("TLS files exist but are invalid or mismatched. Regenerating...");
        }
    }

    if (!generate_self_signed_cert_files(config_.tls_cert_path, config_.tls_key_path)) {
        spdlog::error("Failed to generate TLS files {}, {}", config_.tls_cert_path, config_.tls_key_path);
        return false;
    }

    return save();
}

bool ConfigManager::is_port_available(int port) {
    auto sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == -1) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<unsigned short>(port));

    int res = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return res == 0;
}

HashResult ConfigManager::get_safe_hash(const std::string& password) {

	std::string salt = generate_random_salt(16);

    std::string combined = password + salt;

    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256((unsigned char*)combined.c_str(), combined.size(), hash);

    std::stringstream ss;

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    HashResult result;
    result.salt = salt;
    result.hash = ss.str();
    return result;
}

bool ConfigManager::verify_password(const std::string& input_login, const std::string& input_password) {

    std::string salt = config_.admin_password_salt;
    std::string original_hash = config_.admin_password_hash;


    std::string combined = input_password + salt;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)combined.c_str(), combined.size(), hash);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    bool answer = (input_login == config_.admin_username) && (ss.str() == original_hash);
    return answer;
}

std::string ConfigManager::generate_random_salt(size_t length) {
    std::vector<unsigned char> buffer(length);


    if (RAND_bytes(buffer.data(), static_cast<int>(length)) != 1) {
        spdlog::error("OpenSSL RAND_bytes failed! Using fallback (less secure)");
        return "fallback_salt_" + std::to_string(time(0));
    }

    std::stringstream ss;
    for (auto byte : buffer) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
    }

    return ss.str();

}

bool is_tls_valid(const std::string& cert_path, const std::string& key_path) {
	// 1. Try to load the certificate
    FILE* cert_file = fopen(cert_path.c_str(), "r");
    if (!cert_file) return false;
    X509* cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
    fclose(cert_file);

    if (!cert) return false;

	// 2. Try to load the private key
    FILE* key_file = fopen(key_path.c_str(), "r");
    if (!key_file) {
        X509_free(cert);
        return false;
    }
    EVP_PKEY* pkey = PEM_read_PrivateKey(key_file, nullptr, nullptr, nullptr);
    fclose(key_file);

    if (!pkey) {
        X509_free(cert);
        return false;
    }

	// 3. Maintain the invariant that the cert and key must match
    int match = X509_check_private_key(cert, pkey);

	// Clean up OpenSSL structures 
    X509_free(cert);
    EVP_PKEY_free(pkey);

    return (match == 1);
}