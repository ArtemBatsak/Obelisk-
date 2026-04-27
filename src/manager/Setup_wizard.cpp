#include "Setup_wizard.h"
#include "tls/tls_session.h"
#include <filesystem>

bool ConfigManager::check_config() {
    std::ifstream file("config.json");

    if (!file.good()) {
        return false;
    }

    try {
        load();
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


    auto ask_and_validate = [this](const std::string& name, int def) -> int {
        std::string input;
        int port = def;
        while (true) {
            spdlog::info("Enter {} [default: {}]: ", name, def);
            std::getline(std::cin, input);

            if (!input.empty()) {
                try { port = std::stoi(input); }
                catch (...) { spdlog::error("Invalid number!"); continue; }
            }
            else { port = def; }

            if (is_port_available(port)) {
                return port;
            }
            else {
                spdlog::error("Port {} is BUSY or RESERVED (root?). Try another one.", port);
            }
        }
        };

    config_.control_port = ask_and_validate("Control Port", 44555);
    config_.data_port = ask_and_validate("Data Port", 50021);
    config_.web_port = ask_and_validate("Web Admin Port", 8000);
    spdlog::info("");

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
    config_.tls_cert_path = "obelisk_server.crt";
    config_.tls_key_path = "obelisk_server.key";
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
    std::ifstream file("config.json");
    nlohmann::json j;
    file >> j;
    config_.control_port = j.at("control_port").get<int>();
    config_.data_port = j.at("data_port").get<int>();
    config_.web_port = j.at("web_port").get<int>();
    config_.admin_password_hash = j.at("admin_password_hash").get<std::string>();
    config_.admin_username = j.at("admin_username").get<std::string>();
	config_.admin_password_salt = j.at("admin_password_salt").get<std::string>();
    config_.tls_cert_path = j.value("tls_cert_path", std::string("obelisk_server.crt"));
    config_.tls_key_path = j.value("tls_key_path", std::string("obelisk_server.key"));
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
        std::ofstream file("config.json");
        file << j.dump(4);
        return true;
    }
    catch (const std::exception& e) {
        spdlog::error("Failed to save config: {}", e.what());
        return false;
    }
}

bool ConfigManager::ensure_tls_material() {
    if (config_.tls_cert_path.empty()) {
        config_.tls_cert_path = "obelisk_server.crt";
    }
    if (config_.tls_key_path.empty()) {
        config_.tls_key_path = "obelisk_server.key";
    }

    if (std::filesystem::exists(config_.tls_cert_path) && std::filesystem::exists(config_.tls_key_path)) {
        return true;
    }

    if (!generate_self_signed_cert_files(config_.tls_cert_path, config_.tls_key_path)) {
        spdlog::error("Failed to generate TLS files {}, {}", config_.tls_cert_path, config_.tls_key_path);
        return false;
    }

    return save();
}

bool ConfigManager::is_port_available(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return false;
#endif
    auto sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
#ifdef _WIN32
        WSACleanup();
#endif
        return false;
    }


    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(static_cast<unsigned short>(port));

    int result = bind(sock, (struct sockaddr*)&addr, sizeof(addr));

#ifdef _WIN32
    closesocket(sock);
    WSACleanup();
#else
    close(sock);
#endif
    // if bind returns 0, the port is available; if it returns -1, the port is in use or there's an error
    return result == 0;
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
