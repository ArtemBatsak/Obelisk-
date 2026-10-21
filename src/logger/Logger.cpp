#include "Logger.h"
#include "path/Path.h"
#include <spdlog/spdlog.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>

void init_logging()
{
	//protect against multiple initializations
	if (spdlog::get("obelisk"))
		return;

	constexpr std::size_t max_file_size = 5 * 1024 * 1024;
	constexpr std::size_t max_files = 5;

    auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();

    std::vector<spdlog::sink_ptr> sinks{ console_sink };

	try {
		auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
			Path::LogFile(), max_file_size, max_files
		);
		file_sink->set_level(spdlog::level::info);
		sinks.push_back(file_sink);
	}
	catch (const std::exception& e) {
		spdlog::warn("Failed to open log file '{}': {}. Console-only logging.", Path::LogFile(), e.what());
	}

    console_sink->set_level(spdlog::level::info);

    auto logger = std::make_shared<spdlog::logger>("obelisk", sinks.begin(), sinks.end());
    logger->set_level(spdlog::level::info);
    logger->set_pattern("[%d.%m.%Y %H:%M:%S.%e] [%l] %v");
    logger->flush_on(spdlog::level::info);

    spdlog::set_default_logger(logger);

    spdlog::info("Logger initialized");
}
