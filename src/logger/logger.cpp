#include "logger/logger.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <filesystem>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

void init_logging()
{
    // защита от повторной инициализации
    if (spdlog::get("obelisk"))
        return;

    namespace fs = std::filesystem;

    const fs::path log_dir = "logs";
    fs::create_directories(log_dir);
    const fs::path log_file = log_dir / "obelisk.log";

    constexpr std::size_t max_file_size = 5 * 1024 * 1024;
    constexpr std::size_t max_files = 5;

    // --- создаём sinks ---
    auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        log_file.string(), max_file_size, max_files
    );
    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    file_sink->set_level(spdlog::level::info);
    console_sink->set_level(spdlog::level::info);

    std::vector<spdlog::sink_ptr> sinks{ console_sink, file_sink };

    auto logger = std::make_shared<spdlog::logger>("obelisk", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::info);
    logger->set_pattern("[%d.%m.%Y %H:%M:%S.%e] [%l] %v");
    logger->flush_on(spdlog::level::info);

    spdlog::set_default_logger(logger);

    spdlog::info("Logger initialized");
}
