#include "Setup_wizard.h"

#include <filesystem>
#include <iomanip>
#include <sstream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

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

    if (!file.good()) {
        return false;
    }

    try {
        load();

        if (config_.control_port <= 0 || config_.control_port > 65535||!is_port_available(config_.control_port)) {
            spdlog::error("Invalid control_port in config.json {}", config_.control_port);
            return false;
		}
        if (config_.data_port <= 0 || config_.data_port > 65535||!is_port_available(config_.data_port)) {
            spdlog::error("Invalid data_port in config.json {}", config_.data_port);
			return false;
		}
        if (config_.web_port <= 0 || config_.web_port > 65535||!is_port_available(config_.web_port)) {
            spdlog::error("Invalid web_port in config.json {}", config_.web_port);
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
        
        if (!ensure_tls_material()) {
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        spdlog::error("Failed to parse config.json: {}", e.what());
        return false;
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

        config_.admin_username = j.at("admin_username").get<std::string>();
        config_.admin_password_hash = j.at("admin_password_hash").get<std::string>();
        config_.admin_password_salt = j.at("admin_password_salt").get<std::string>();

        config_.tls_cert_path = j.value("tls_cert_path", TLS_CERT_PATH);
        config_.tls_key_path = j.value("tls_key_path", TLS_KEY_PATH);

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
    j["admin_password_hash"] = config_.admin_password_hash;
    j["admin_username"] = config_.admin_username;
	j["admin_password_salt"] = config_.admin_password_salt;
    j["tls_cert_path"] = config_.tls_cert_path;
    j["tls_key_path"] = config_.tls_key_path;
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