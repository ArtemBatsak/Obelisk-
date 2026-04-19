#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <future>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <asio.hpp>
#include <asio/ssl.hpp>

#include "logger/Logger.h"
#include "manager/Data.h"
#include "manager/Server_manager.h"
#include "manager/Setup_Wizard.h"

namespace fs = std::filesystem;
using asio::ip::tcp;

namespace {

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

        explicit TestGrayConnector(asio::io_context& io)
            : io_(io),
            ssl_ctx_(asio::ssl::context::tlsv12_client),
            ssl_sock_(std::make_shared<asio::ssl::stream<tcp::socket>>(io_, ssl_ctx_)) {
            ssl_ctx_.set_verify_mode(asio::ssl::verify_none);
            ssl_ctx_.set_options(
                asio::ssl::context::default_workarounds |
                asio::ssl::context::no_sslv2 |
                asio::ssl::context::no_sslv3
            );
        }

        AuthResult connect_to_obelisk_server(const std::string& server_ip, uint16_t control_port, uint32_t id_client, uint32_t pool_size) {
            tcp::resolver resolver(io_);
            auto endpoints = resolver.resolve(server_ip, std::to_string(control_port));
            asio::connect(ssl_sock_->lowest_layer(), endpoints);
            ssl_sock_->handshake(asio::ssl::stream_base::client);

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

    TEST(ConfigManagerTest, CreatesAndLoadsConfigFile) {
        ScopedTempDir temp;

        auto wizard = std::make_shared<ConfigManager>();
        EXPECT_FALSE(wizard->check_config());

        std::istringstream fake_input("\n\n\n\nstrongpass\n");
        auto* old_in = std::cin.rdbuf(fake_input.rdbuf());
        wizard->set_up();
        std::cin.rdbuf(old_in);

        EXPECT_TRUE(fs::exists("config.json"));

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

    TEST(StartupAndServerFlowTest, CreatesCoreObjectsAuthorizesGrayServerTransfers10MbAndShutsDown) {
        ScopedTempDir temp;

        init_logging();
        spdlog::info("Obelisk started");

        asio::io_context io;

        const uint16_t control_port = reserve_free_port(io);
        const uint16_t data_port = reserve_free_port(io);
        const uint16_t web_port = reserve_free_port(io);

        {
            std::ofstream cfg("config.json");
            cfg << "{\n"
                "  \"control_port\": " << control_port << ",\n"
                "  \"data_port\": " << data_port << ",\n"
                "  \"web_port\": " << web_port << ",\n"
                "  \"admin_password_hash\": \"h\",\n"
                "  \"admin_username\": \"admin\",\n"
                "  \"admin_password_salt\": \"s\"\n"
                "}";
        }

        auto wizard = std::make_shared<ConfigManager>();
        ASSERT_TRUE(wizard->check_config());
        auto cfg = wizard->get_config();

        auto running = std::make_shared<std::atomic<bool>>(true);
        auto data_servers = std::make_shared<DataServers>();
        ASSERT_TRUE(data_servers->add_ports(31000, 31010));
        ASSERT_TRUE(data_servers->add_id("integration-gray"));

        auto servers = data_servers->get_servers();
        ASSERT_EQ(servers.size(), 1u);
        const uint32_t gray_id = static_cast<uint32_t>(servers[0].id);

        auto server_manager = std::make_shared<ServerManager>(
            running,
            cfg.control_port,
            cfg.data_port,
            data_servers,
            io.get_executor()
        );

        ASSERT_NE(wizard, nullptr);
        ASSERT_NE(data_servers, nullptr);
        ASSERT_NE(server_manager, nullptr);

        server_manager->start();

        std::thread io_thread([&io]() { io.run(); });

        TestGrayConnector test_gray(io);
        auto auth = test_gray.connect_to_obelisk_server("127.0.0.1", static_cast<uint16_t>(cfg.control_port), gray_id, 1);
        test_gray.set_assigned_data_port(static_cast<uint16_t>(auth.data_port));

        EXPECT_EQ(auth.server_id, gray_id);
        EXPECT_TRUE(server_manager->server_online(gray_id));

        auto gray_data_socket = test_gray.wait_for_data_socket(std::chrono::seconds(3));
        ASSERT_NE(gray_data_socket, nullptr);

        tcp::socket external_client(io);
        external_client.connect({ asio::ip::address_v4::loopback(), static_cast<uint16_t>(auth.client_port) });

        constexpr std::size_t payload_size = 10 * 1024 * 1024;
        std::vector<char> payload(payload_size, 'K');
        std::vector<char> received(payload_size, 0);

        std::thread reader([&]() {
            asio::read(*gray_data_socket, asio::buffer(received));
            });

        asio::write(external_client, asio::buffer(payload));
        reader.join();

        EXPECT_EQ(payload, received);

        EXPECT_GE(server_manager->get_active_pairs(gray_id), 1u);
        EXPECT_GE(server_manager->get_ping(gray_id), 0u);

        asio::error_code ec;
        external_client.shutdown(tcp::socket::shutdown_both, ec);
        external_client.close(ec);

        std::this_thread::sleep_for(std::chrono::milliseconds(400));
        EXPECT_EQ(server_manager->get_active_pairs(gray_id), 0u);

        EXPECT_TRUE(server_manager->shutdown_id(gray_id));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        EXPECT_FALSE(server_manager->server_online(gray_id));

        auto after = data_servers->get_servers();
        ASSERT_EQ(after.size(), 1u);
        EXPECT_GE(after[0].total_traffic, 0u);

        test_gray.stop();
        server_manager->shutdown_all();
        *running = false;
        io.stop();

        if (io_thread.joinable()) {
            io_thread.join();
        }

        server_manager.reset();
        data_servers.reset();
        wizard.reset();
    }

}