#pragma once

#include <filesystem>
#include <string>

namespace Path
{
    std::string ConfigDir();
    std::string ConfigFile();

    std::string CertFile();
    std::string KeyFile();

    std::string LogDir();
    std::string LogFile();

    void EnsureDirs();

    // Data storage paths
    std::filesystem::path DataConfigsDirPath();
    std::filesystem::path DataServersFilePath();
    std::filesystem::path DataPortsFilePath();

    // Ensure files exist
    void EnsureDataFiles();      // Create data files (Servers.txt, Port.txt) if missing
    void EnsureLogFiles();       // Create log file if missing
}