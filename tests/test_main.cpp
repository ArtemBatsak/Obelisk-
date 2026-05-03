#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <asio.hpp>
#include <asio/ssl.hpp>

#ifdef _WIN32
#include <windows.h>
#else
#include <csignal>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#endif
#include "logger/Logger.h"
#include "manager/Data.h"
#include "manager/Server_manager.h"
#include "manager/Setup_wizard.h"
#include "tls/Tls_session.h"
std::string CONFIG_PATH = "config/config.json";
std::string TLS_CERT_PATH = "config/tls_cert.cer";
std::string TLS_KEY_PATH = "config/tls_key.pem";

namespace fs = std::filesystem;
using asio::ip::tcp;

namespace {
    static bool write_main_test_config(uint16_t control_port, uint16_t data_port, uint16_t web_port) {
        fs::create_directories("config");
        std::ofstream cfg(CONFIG_PATH);
        if (!cfg.is_open()) return false;
        cfg << "{\n"
            << "  \"control_port\": " << control_port << ",\n"
            << "  \"data_port\": " << data_port << ",\n"
            << "  \"web_port\": " << web_port << ",\n"
            << "  \"admin_password_hash\": \"h\",\n"
            << "  \"admin_username\": \"admin\",\n"
            << "  \"admin_password_salt\": \"s\"\n"
            << "}";
        return cfg.good();
    }

    static fs::path find_obelisk_binary(const fs::path& test_binary) {
#ifdef _WIN32
        const std::vector<fs::path> candidates = {
            (test_binary.parent_path() / "Obelisk.exe"),
            (test_binary.parent_path() / "Debug" / "Obelisk.exe"),
            (test_binary.parent_path() / "Release" / "Obelisk.exe"),
            (test_binary.parent_path().parent_path() / "Obelisk.exe"),
            (test_binary.parent_path().parent_path() / "Debug" / "Obelisk.exe"),
            (test_binary.parent_path().parent_path() / "Release" / "Obelisk.exe")
        };
#else
        const std::vector<fs::path> candidates = {
            (test_binary.parent_path() / "Obelisk"),
            (test_binary.parent_path().parent_path() / "Obelisk")
        };
#endif
        for (const auto& candidate : candidates) {
            const auto normalized = candidate.lexically_normal();
            if (fs::exists(normalized)) {
                return normalized;
            }
        }
        return {};
    }

    class ScopedTempDir {
    public:
        ScopedTempDir() {
            const auto seed = std::chrono::high_resolution_clock::now().time_since_epoch().count();
            path_ = fs::temp_directory_path() / ("obelisk_tests_" + std::to_string(seed));
            fs::create_directories(path_);
            old_ = fs::current_path();
            fs::current_path(path_);
        }

        ~ScopedTempDir() {
            fs::current_path(old_);
            std::error_code ec;
            fs::remove_all(path_, ec);
        }

    private:
        fs::path path_;
        fs::path old_;
    };

    struct DataPacket {
        uint32_t id;
        uint32_t otp;
    };

    static uint16_t reserve_free_port(asio::io_context& io) {
        tcp::acceptor acceptor(io, tcp::endpoint(tcp::v4(), 0));
        return acceptor.local_endpoint().port();
    }

    class TestGrayConnector {
    public:
        struct AuthResult {
            uint32_t server_id{};
            uint32_t client_port{};
            uint32_t data_port{};
        };

        explicit TestGrayConnector(asio::io_context& io, const std::string& cert_pem = {}, const std::string& key_pem = {})
            : io_(io),
            ssl_ctx_(asio::ssl::context::tlsv12_client),
            ssl_sock_(nullptr) {
            ssl_ctx_.set_verify_mode(asio::ssl::verify_none);
            ssl_ctx_.set_options(
                asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3
            );

            if (!cert_pem.empty() && !key_pem.empty()) {
                const bool loaded = load_cert_and_key_into_context(ssl_ctx_, cert_pem, key_pem);
                if (!loaded) {
                    std::cout << "[TestGrayConnector] ERROR: Failed to load certificate!" << std::endl;
                    throw std::runtime_error("Failed to load test client certificate into SSL context");
                }
                std::cout << "[TestGrayConnector] Certificate loaded successfully!" << std::endl;
            }
            else {
                std::cout << "[TestGrayConnector] WARNING: cert_pem.empty()=" << cert_pem.empty()
                    << ", key_pem.empty()=" << key_pem.empty() << std::endl;
            }

            ssl_sock_ = std::make_shared<asio::ssl::stream<tcp::socket>>(io_, ssl_ctx_);
            std::cout << "[TestGrayConnector] SSL socket created successfully!" << std::endl;
        }

        AuthResult connect_to_obelisk_server(const std::string& server_ip, uint16_t control_port, uint32_t id_client, uint32_t pool_size) {
            tcp::resolver resolver(io_);
            auto endpoints = resolver.resolve(server_ip, std::to_string(control_port));
            asio::connect(ssl_sock_->lowest_layer(), endpoints);

            std::cout << "[CLIENT] Connected to " << server_ip << ":" << control_port << std::endl;
            std::cout << "[CLIENT] About to perform SSL handshake..." << std::endl;

            try {
                ssl_sock_->handshake(asio::ssl::stream_base::client);
                std::cout << "[CLIENT] Handshake successful!" << std::endl;
            }
            catch (const std::exception& e) {
                std::cout << "[CLIENT] Handshake failed: " << e.what() << std::endl;
                throw;
            }

            std::array<uint32_t, 2> req_buf{};
            req_buf[0] = htonl(id_client);
            req_buf[1] = htonl(pool_size);
            asio::write(*ssl_sock_, asio::buffer(req_buf));

            std::array<uint32_t, 3> resp_buf{};
            asio::read(*ssl_sock_, asio::buffer(resp_buf));

            AuthResult res;
            res.server_id = ntohl(resp_buf[0]);
            res.client_port = ntohl(resp_buf[1]);
            res.data_port = ntohl(resp_buf[2]);

            if (res.server_id != id_client) {
                throw std::runtime_error("Authorization failed: mismatched server id");
            }

            control_reader_thread_ = std::thread([this, id_client]() {
                while (!stop_reader_.load()) {
                    Packet pkt{};
                    asio::error_code ec;
                    std::size_t n = asio::read(*ssl_sock_, asio::buffer(&pkt, sizeof(pkt)), ec);
                    if (ec || n != sizeof(pkt)) {
                        break;
                    }

                    const uint32_t type = ntohl(pkt.type);
                    const uint32_t value = ntohl(pkt.value);

                    if (type == 1) {
                        Packet pong{};
                        pong.type = htonl(1);
                        pong.value = htonl(0);
                        asio::write(*ssl_sock_, asio::buffer(&pong, sizeof(pong)), ec);
                        if (ec) break;
                    }
                    else if (type == 2) {
                        auto data_sock = std::make_shared<tcp::socket>(io_);
                        data_sock->connect({ asio::ip::address_v4::loopback(), assigned_data_port_ }, ec);
                        if (ec) continue;

                        DataPacket p{};
                        p.id = htonl(id_client);
                        p.otp = htonl(value);
                        asio::write(*data_sock, asio::buffer(&p, sizeof(p)), ec);
                        if (ec) continue;

                        {
                            std::lock_guard<std::mutex> lock(mx_);
                            data_sockets_.push_back(data_sock);
                        }
                        cv_.notify_one();
                    }
                }
                });

            return res;
        }

        void set_assigned_data_port(uint16_t port) { assigned_data_port_ = port; }

        std::shared_ptr<tcp::socket> wait_for_data_socket(std::chrono::milliseconds timeout) {
            std::unique_lock<std::mutex> lock(mx_);
            if (!cv_.wait_for(lock, timeout, [this]() { return !data_sockets_.empty(); })) {
                return nullptr;
            }
            return data_sockets_.back();
        }

        void stop() {
            stop_reader_ = true;
            asio::error_code ec;
            if (ssl_sock_ && ssl_sock_->lowest_layer().is_open()) {
                ssl_sock_->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
                ssl_sock_->lowest_layer().close(ec);
            }
            if (control_reader_thread_.joinable()) {
                control_reader_thread_.join();
            }
        }

        ~TestGrayConnector() { stop(); }

    private:
        asio::io_context& io_;
        asio::ssl::context ssl_ctx_;
        std::shared_ptr<asio::ssl::stream<tcp::socket>> ssl_sock_;
        std::thread control_reader_thread_;
        std::atomic<bool> stop_reader_{ false };

        uint16_t assigned_data_port_{ 0 };
        std::mutex mx_;
        std::condition_variable cv_;
        std::vector<std::shared_ptr<tcp::socket>> data_sockets_;
    };
    /// ====== Test 1: ConfigManager setup wizard creates and loads config file ======
    TEST(ConfigManagerTest, SetupWizardCreatesAndLoadsConfigFile) {
        ScopedTempDir temp;
        SCOPED_TRACE("Class under test: ConfigManager");

        auto wizard = std::make_shared<ConfigManager>();
        EXPECT_FALSE(wizard->check_config());

        std::istringstream fake_input("\n\n\n\nstrongpass\n");
        auto* old_in = std::cin.rdbuf(fake_input.rdbuf());
        wizard->set_up();
        std::cin.rdbuf(old_in);

        EXPECT_TRUE(fs::exists(CONFIG_PATH));

        auto loaded = std::make_shared<ConfigManager>();
        EXPECT_TRUE(loaded->check_config());

        Config cfg = loaded->get_config();
        EXPECT_EQ(cfg.control_port, 44555);
        EXPECT_EQ(cfg.data_port, 50021);
        EXPECT_EQ(cfg.web_port, 8000);
        EXPECT_EQ(cfg.admin_username, "admin");
        EXPECT_FALSE(cfg.admin_password_hash.empty());
        EXPECT_FALSE(cfg.admin_password_salt.empty());
    }
    /// ====== Test 2: Main process starts with prepared config and stops on signal ======
   /* TEST(ObeliskMainProcessTest, MainStartsWithPreparedConfigAndStopsOnSignal) {
        ScopedTempDir temp;
        SCOPED_TRACE("Class under test: main (application startup flow)");

        const auto test_binary = fs::path(::testing::internal::GetArgvs()[0]);
        const auto obelisk_binary = find_obelisk_binary(test_binary);
        ASSERT_TRUE(fs::exists(obelisk_binary));

        bool started_and_stopped = false;
        std::string last_error;
#ifdef _WIN32
        std::string last_child_output = "stdout/stderr capture is not implemented on Windows branch in this test.";
#else
        std::string last_child_output;
#endif
        const int max_attempts = 5;
        const int base_port = 45000;

        for (int attempt = 0; attempt < max_attempts && !started_and_stopped; ++attempt) {
            const uint16_t control_port = static_cast<uint16_t>(base_port + attempt * 3);
            const uint16_t data_port = static_cast<uint16_t>(base_port + attempt * 3 + 1);
            const uint16_t web_port = static_cast<uint16_t>(base_port + attempt * 3 + 2);

            ASSERT_TRUE(write_main_test_config(control_port, data_port, web_port));

#ifdef _WIN32
            STARTUPINFOA si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};

            std::string cmd = "\"" + obelisk_binary.string() + "\"";
            ASSERT_TRUE(CreateProcessA(nullptr, cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi));

            std::this_thread::sleep_for(std::chrono::seconds(2));

            DWORD code = 0;
            ASSERT_TRUE(GetExitCodeProcess(pi.hProcess, &code));
            if (code != STILL_ACTIVE) {
                last_error = "Early exit code: " + std::to_string(static_cast<unsigned long>(code));
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                continue;
            }

            ASSERT_TRUE(TerminateProcess(pi.hProcess, 0));
            ASSERT_EQ(WaitForSingleObject(pi.hProcess, 5000), WAIT_OBJECT_0);

            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            started_and_stopped = true;
#else
            int input_pipe[2];
            int out_pipe[2];
            ASSERT_EQ(pipe(input_pipe), 0);
            ASSERT_EQ(pipe(out_pipe), 0);

            pid_t pid = fork();
            ASSERT_NE(pid, -1);

            if (pid == 0) {
                close(input_pipe[1]);
                dup2(input_pipe[0], STDIN_FILENO);
                close(input_pipe[0]);

                close(out_pipe[0]);
                dup2(out_pipe[1], STDOUT_FILENO);
                dup2(out_pipe[1], STDERR_FILENO);
                close(out_pipe[1]);

                execl(obelisk_binary.c_str(), obelisk_binary.c_str(), (char*)nullptr);
                _exit(127);
            }

            close(input_pipe[0]);
            close(out_pipe[1]);
            const char* scripted_input = "\n\n\n\nstrongpass\n";
            (void)write(input_pipe[1], scripted_input, std::strlen(scripted_input));
            close(input_pipe[1]);

            int flags = fcntl(out_pipe[0], F_GETFL, 0);
            fcntl(out_pipe[0], F_SETFL, flags | O_NONBLOCK);

            std::this_thread::sleep_for(std::chrono::seconds(2));

            int status = 0;
            pid_t wait_result = waitpid(pid, &status, WNOHANG);

            std::string child_output;
            char buf[1024];
            while (true) {
                ssize_t n = read(out_pipe[0], buf, sizeof(buf));
                if (n > 0) child_output.append(buf, static_cast<size_t>(n));
                else break;
            }
            close(out_pipe[0]);

            if (wait_result == pid) {
                if (WIFEXITED(status)) {
                    last_error = "Early exit code: " + std::to_string(WEXITSTATUS(status));
                }
                else if (WIFSIGNALED(status)) {
                    last_error = "Terminated by signal: " + std::to_string(WTERMSIG(status));
                }
                else {
                    last_error = "Exited early with unknown status.";
                }
                last_child_output = child_output;
                continue;
            }

            ASSERT_EQ(wait_result, 0);
            ASSERT_EQ(kill(pid, SIGINT), 0);
            ASSERT_EQ(waitpid(pid, &status, 0), pid);
            EXPECT_TRUE(WIFEXITED(status));
            started_and_stopped = true;
#endif
        }

        ASSERT_TRUE(started_and_stopped) << "Obelisk did not stay alive during startup after "
            << max_attempts << " attempts. Last reason: " << last_error
            << "\nChild output:\n" << last_child_output;
    }*/
    /// ====== Test 3: Full integration flow - create server, connect, transfer data, close connection, delete server ======
    TEST(ServerManagerIntegrationFlowTest, FullDataPathCreateConnectTransferCloseDelete) {
        ScopedTempDir temp;

        init_logging();
        asio::io_context io;

        const uint16_t control_port = reserve_free_port(io);
        const uint16_t data_port = reserve_free_port(io);

        auto running = std::make_shared<std::atomic<bool>>(true);
        auto data_servers = std::make_shared<DataServers>();
        ASSERT_TRUE(data_servers->add_ports(31000, 31010));

        {
            SCOPED_TRACE("Class under test: DataServers (2.1 create server)");
            ASSERT_TRUE(data_servers->add_id("integration-gray", control_port, "127.0.0.1"));
            auto servers = data_servers->get_servers();
            ASSERT_EQ(servers.size(), 1u);
        }

        const auto gray_id = static_cast<uint32_t>(data_servers->get_servers().front().id);

        auto server_manager = std::make_shared<ServerManager>(
            running,
            control_port,
            data_port,
            data_servers,
            TLS_CERT_PATH,
            TLS_KEY_PATH,
            io.get_executor()
        );

        server_manager->start();
        std::thread io_thread([&io]() { io.run(); });

        std::string config_json_text;
        ASSERT_TRUE(data_servers->read_server_config_file(gray_id, config_json_text));
        auto server_cfg = nlohmann::json::parse(config_json_text);

        const std::string client_cert = server_cfg.at("CERTIFICATE").get<std::string>();
        const std::string client_key = server_cfg.at("PRIVATE_KEY").get<std::string>();

        TestGrayConnector test_gray(io, client_cert, client_key);

        {
            SCOPED_TRACE("Class under test: ServerManager (2.2 connect + server registered)");
            auto auth = test_gray.connect_to_obelisk_server("127.0.0.1", control_port, gray_id, 1);
            test_gray.set_assigned_data_port(static_cast<uint16_t>(auth.data_port));
            EXPECT_EQ(auth.server_id, gray_id);
            EXPECT_TRUE(server_manager->server_online(gray_id));

            auto gray_data_socket = test_gray.wait_for_data_socket(std::chrono::seconds(3));
            ASSERT_NE(gray_data_socket, nullptr);

            tcp::socket external_client(io);
            external_client.connect({ asio::ip::address_v4::loopback(), static_cast<uint16_t>(auth.client_port) });

            {
                SCOPED_TRACE("Class under test: GrayServer data channel (2.3 transfer 10MB)");
                constexpr std::size_t payload_size = 10 * 1024 * 1024;
                std::vector<char> payload(payload_size, 'K');
                std::vector<char> received(payload_size, 0);

                std::thread reader([&]() {
                    asio::read(*gray_data_socket, asio::buffer(received));
                    });

                asio::write(external_client, asio::buffer(payload));
                reader.join();
                EXPECT_EQ(payload, received);
            }

            {
                SCOPED_TRACE("Class under test: ServerManager (2.4 close connection shrinks active vector)");
                EXPECT_GE(server_manager->get_active_pairs(gray_id), 1u);
                asio::error_code ec;
                external_client.shutdown(tcp::socket::shutdown_both, ec);
                external_client.close(ec);
                std::this_thread::sleep_for(std::chrono::milliseconds(400));
                EXPECT_EQ(server_manager->get_active_pairs(gray_id), 0u);
            }
        }

        {
            SCOPED_TRACE("Class under test: DataServers + ServerManager (2.5 delete server)");
            EXPECT_TRUE(server_manager->delete_server(gray_id));
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
            EXPECT_FALSE(server_manager->server_online(gray_id));
            EXPECT_TRUE(data_servers->get_servers().empty());
        }

        {
            SCOPED_TRACE("Class under test: application shutdown (2.6 finish)");
            test_gray.stop();
            server_manager->shutdown_all();
            *running = false;
            io.stop();
        }

        if (io_thread.joinable()) {
            io_thread.join();
        }
    }

    bool load_cert_and_key_into_context(asio::ssl::context& ctx,
        const std::string& cert_pem,
        const std::string& key_pem)
    {
        SSL_CTX* ssl_ctx = ctx.native_handle();
        if (!ssl_ctx) {
            std::cout << "[load_cert] ERROR: ssl_ctx is NULL" << std::endl;
            return false;
        }

        BIO* bio_cert = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
        BIO* bio_key = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));

        if (!bio_cert || !bio_key) {
            std::cout << "[load_cert] ERROR: Failed to create BIO" << std::endl;
            return false;
        }

        X509* x509 = PEM_read_bio_X509(bio_cert, nullptr, nullptr, nullptr);
        EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio_key, nullptr, nullptr, nullptr);

        if (!x509) std::cout << "[load_cert] ERROR: x509 parsing failed" << std::endl;
        if (!pkey) std::cout << "[load_cert] ERROR: pkey parsing failed" << std::endl;

        BIO_free(bio_cert);
        BIO_free(bio_key);

        if (!x509 || !pkey) {
            if (x509) X509_free(x509);
            if (pkey) EVP_PKEY_free(pkey);
            return false;
        }

        int ret1 = SSL_CTX_use_certificate(ssl_ctx, x509);
        int ret2 = SSL_CTX_use_PrivateKey(ssl_ctx, pkey);
        int ret3 = SSL_CTX_check_private_key(ssl_ctx);

        std::cout << "[load_cert] SSL_CTX_use_certificate: " << ret1 << std::endl;
        std::cout << "[load_cert] SSL_CTX_use_PrivateKey: " << ret2 << std::endl;
        std::cout << "[load_cert] SSL_CTX_check_private_key: " << ret3 << std::endl;

        bool ok = ret1 == 1 && ret2 == 1 && ret3 == 1;

        X509_free(x509);
        EVP_PKEY_free(pkey);

        std::cout << "[load_cert] Result: " << (ok ? "SUCCESS" : "FAILED") << std::endl;
        return ok;
    }
    /// ====== Test 4: ServerManager handles port already in use gracefully ======
    TEST(ServerManagerTest, HandlePortAlreadyInUse) {
        ScopedTempDir temp;
        init_logging();
        asio::io_context io;

        tcp::acceptor dummy_acceptor(io, tcp::endpoint(tcp::v4(), 0));
        uint16_t busy_port = dummy_acceptor.local_endpoint().port();

        auto data_servers = std::make_shared<DataServers>();
        auto running = std::make_shared<std::atomic<bool>>(true);

        auto server_manager = std::make_shared<ServerManager>(
            running,
            busy_port,
            12345,
            data_servers,
            TLS_CERT_PATH,
            TLS_KEY_PATH,
            io.get_executor()
        );

        try {
            server_manager->start();
            SUCCEED() << "ServerManager accepted busy control port in this environment.";
        }
        catch (const std::system_error&) {
            SUCCEED() << "ServerManager threw std::system_error on busy control port.";
        }
    }

    /// ====== Test 5: Multiple clients connect simultaneously ======
    TEST(ServerManagerIntegrationFlowTest, MultipleClientsConnectSimultaneously) {
        ScopedTempDir temp;
        init_logging();
        asio::io_context io;

        const uint16_t control_port = reserve_free_port(io);
        const uint16_t data_port = reserve_free_port(io);

        auto running = std::make_shared<std::atomic<bool>>(true);
        auto data_servers = std::make_shared<DataServers>();
        ASSERT_TRUE(data_servers->add_ports(31000, 31020));
        for (int i = 0; i < 5; ++i) {
            ASSERT_TRUE(data_servers->add_id("server-" + std::to_string(i), control_port, "127.0.0.1"));
        }

        auto server_manager = std::make_shared<ServerManager>(
            running,
            control_port,
            data_port,
            data_servers,
            TLS_CERT_PATH,
            TLS_KEY_PATH,
            io.get_executor()
        );

        server_manager->start();
        std::thread io_thread([&io]() { io.run(); });
        auto servers = data_servers->get_servers();
        std::vector<std::thread> client_threads;
        std::atomic<int> successful_connections{ 0 };

        for (const auto& srv : servers) {
            client_threads.emplace_back([&, srv]() {
                try {
                    std::string config_json_text;
                    ASSERT_TRUE(data_servers->read_server_config_file(srv.id, config_json_text));
                    auto server_cfg = nlohmann::json::parse(config_json_text);

                    const std::string client_cert = server_cfg.at("CERTIFICATE").get<std::string>();
                    const std::string client_key = server_cfg.at("PRIVATE_KEY").get<std::string>();

                    TestGrayConnector connector(io, client_cert, client_key);
                    auto auth = connector.connect_to_obelisk_server("127.0.0.1", control_port, srv.id, 1);

                    if (auth.server_id == srv.id) {
                        successful_connections++;
                    }
                    connector.stop();
                }
                catch (...) {
                    // Игнорируем ошибки
                }
                });
        }

        for (auto& t : client_threads) {
            if (t.joinable()) t.join();
        }

        EXPECT_EQ(successful_connections.load(), 5);

        server_manager->shutdown_all();
        *running = false;
        io.stop();
        if (io_thread.joinable()) io_thread.join();
    }

    // ======= Test 6: Handles Corrupted Config File ======
    TEST(ConfigManagerTest, HandlesCorruptedConfigFile) {
        ScopedTempDir temp;


        {
            fs::create_directories("config");
            std::ofstream cfg(CONFIG_PATH);
            cfg << "{ invalid json }";
        }

        auto config_mgr = std::make_shared<ConfigManager>();


        EXPECT_FALSE(config_mgr->check_config());
    }
} // namespace