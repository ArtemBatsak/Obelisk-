#include "Path.h"
#include <iostream>
#include <fstream>

#ifdef _WIN32
#include <windows.h>
#endif

namespace fs = std::filesystem;


namespace
{
    // Get application executable directory (on Windows)
    fs::path GetAppDir()
    {
#ifdef _WIN32
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(NULL, path, MAX_PATH)) {
            return fs::path(path).parent_path();
        }
        // Fallback to current directory if GetModuleFileName fails
        return fs::current_path();
#else
        return fs::current_path();
#endif
    }

    // Get obelisk base directory (same on all platforms)
    fs::path GetObeliskBaseDir()
    {
#ifdef _WIN32
        // On Windows, use "obelisk" folder next to executable
        return GetAppDir() / "obelisk";
#else
        // On Unix: /etc/obelisk
        return fs::path("/etc/obelisk");
#endif
    }

    // Get log subdirectory within obelisk base
    fs::path GetLogDir()
    {
        return GetObeliskBaseDir() / "logs";
    }
}

namespace Path
{
    std::string ConfigDir()
    {
        return GetObeliskBaseDir().string();
    }

    std::string ConfigFile()
    {
        return (GetObeliskBaseDir() / "config.json").string();
    }

    std::string CertFile()
    {
        return (GetObeliskBaseDir() / "tls_cert.cer").string();
    }

    std::string KeyFile()
    {
        return (GetObeliskBaseDir() / "tls_key.pem").string();
    }

    std::string LogDir()
    {
        return GetLogDir().string();
    }

    std::string LogFile()
    {
        return (GetLogDir() / "obelisk.log").string();
    }

    // Data storage locations: configs directory and files
    std::filesystem::path DataConfigsDirPath()
    {
        return GetObeliskBaseDir() / "Gray_servers config";
    }

    std::filesystem::path DataServersFilePath()
    {
        return DataConfigsDirPath() / "Servers.txt";
    }

    std::filesystem::path DataPortsFilePath()
    {
        return DataConfigsDirPath() / "Port.txt";
    }

    void EnsureDirs()
    {
        try {
            std::filesystem::create_directories(fs::path(ConfigDir()));
            std::filesystem::create_directories(GetLogDir());
            std::filesystem::create_directories(DataConfigsDirPath());
        } catch (const std::exception& e) {
            std::cerr << "Failed to create directories: " << e.what() << std::endl;
        }
    }

    void EnsureDataFiles()
    {
        try {
            // Create Servers.txt if missing
            auto servers_file = DataServersFilePath();
            if (!std::filesystem::exists(servers_file)) {
                std::ofstream(servers_file).close();
            }

            // Create Port.txt if missing
            auto ports_file = DataPortsFilePath();
            if (!std::filesystem::exists(ports_file)) {
                std::ofstream(ports_file).close();
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to create data files: " << e.what() << std::endl;
        }
    }

    void EnsureLogFiles()
    {
        try {
            // Create obelisk.log if missing
            auto log_file = LogFile();
            if (!std::filesystem::exists(log_file)) {
                std::ofstream(log_file).close();
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to create log files: " << e.what() << std::endl;
        }
    }
}