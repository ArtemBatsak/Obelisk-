#include "manager/Data.h"


// --------------- ServerManager methods----------
void ServerManager::add(std::shared_ptr<GrayServer> server) {
    std::lock_guard<std::mutex> lock(mtx_);
    servers_.push_back(std::move(server));
}

void ServerManager::remove(uint32_t id) {
    std::lock_guard<std::mutex> lock(mtx_);

    auto before = servers_.size();

    servers_.erase(
        std::remove_if(
            servers_.begin(),
            servers_.end(),
            [id](const std::shared_ptr<GrayServer>& s) {
                return s && s->get_id() == id;
            }),
        servers_.end()
    );

    if (before != servers_.size()) {
        std::cout << "GrayServer " << id << " removed from manager\n";
    }
}

void ServerManager::shutdown_all() {
    std::vector<std::shared_ptr<GrayServer>> copy;

    {
        std::lock_guard<std::mutex> lock(mtx_);
        copy = servers_;
        servers_.clear();
    }

    for (auto& s : copy) {
        if (s) s->shutdown();
    }

    spdlog::info("All GrayServers shutdown requested");
}


// ---------------- Server_struct ----------------
std::string Server_struct::to_string() const {
    return "{ \"id\": " + std::to_string(id)
        + ", \"client_port\": " + std::to_string(client_port)
        + ", \"data_port\": " + std::to_string(data_port)
        + ", \"comment\": \"" + comment + "\" }";
}

Server_struct Server_struct::from_string(const std::string& line) {
    Server_struct entry;
    std::size_t pos1, pos2;

    pos1 = line.find("\"id\": ");
    pos2 = line.find(",", pos1);
    entry.id = std::stoi(line.substr(pos1 + 6, pos2 - (pos1 + 6)));

    pos1 = line.find("\"client_port\": ");
    pos2 = line.find(",", pos1);
    entry.client_port = std::stoi(line.substr(pos1 + 15, pos2 - (pos1 + 15)));

    pos1 = line.find("\"data_port\": ");
    pos2 = line.find(",", pos1);
    entry.data_port = std::stoi(line.substr(pos1 + 13, pos2 - (pos1 + 13)));

    pos1 = line.find("\"comment\": \"");
    pos2 = line.rfind("\"");
    entry.comment = line.substr(pos1 + 12, pos2 - (pos1 + 12));

    return entry;
}

// ---------------- DataServers ----------------
DataServers::DataServers() {
    std::srand(static_cast<unsigned int>(std::time(nullptr)));
    ensure_file();
    read_id();
    read_ports();
}

void DataServers::ensure_file() {
    std::ofstream(id_file, std::ios::app).close();
    std::ofstream(port_file, std::ios::app).close();
}

void DataServers::read_id() {
    std::lock_guard<std::mutex> lock(mtx_);
    servers_id.clear();
    std::ifstream infile(id_file);
    if (!infile.is_open()) return;

    std::string line;
    while (std::getline(infile, line)) {
        if (!line.empty()) {
            try {
                servers_id.push_back(Server_struct::from_string(line));
            }
            catch (...) {
                spdlog::error("Error parsing line: {}", line);
            }
        }
    }
}

void DataServers::read_ports() {
    std::lock_guard<std::mutex> lock(mtx_);
    std::ifstream infile(port_file);
    if (!infile.is_open()) {
        spdlog::error("Error: cannot open {}", port_file);
        return;
    }

    infile.seekg(0, std::ios::end);
    if (infile.tellg() == 0) {
        int start, end;
        spdlog::info("Port file is empty. Enter a port range (e.g., 50000 50020): ");
        std::cin >> start >> end;

        std::ofstream outfile(port_file, std::ios::trunc);
        for (int p = start; p <= end; ++p) {
            outfile << p << "\n";
        }
        outfile.close();
    }

    infile.clear();
    infile.seekg(0, std::ios::beg);
    ports.clear();
    int port;
    while (infile >> port) {
        ports.push_back(port);
    }
    infile.close();

    spdlog::info("Loaded {} ports.", ports.size());

}

int DataServers::gen_id() {
    int new_id;
    bool exists;
    do {
        new_id = std::rand() % 9000000 + 1000000;
        exists = false;
        for (const auto& s : servers_id) {
            if (s.id == new_id) {
                exists = true;
                break;
            }
        }
    } while (exists);
    return new_id;
}

void DataServers::add_id() {
    
    {
        std::lock_guard<std::mutex> lock(mtx_);
        if (ports.size() < 2) {
            spdlog::error("Error: not enough free ports available for a new server!");
            return;
        }
    }

    std::string comment_;
    spdlog::info("Enter a comment for the new server: ");
    //std::cin.ignore();
    std::getline(std::cin, comment_);

    int client_port_;
    int data_port_;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        // ещё раз проверить и достать порты под защитой
        if (ports.size() < 2) {
            spdlog::error("Error: not enough free ports available for a new server!");
            return;
        }

        client_port_ = ports.back(); ports.pop_back();
        data_port_ = ports.back(); ports.pop_back();

        Server_struct entry;
        entry.id = gen_id();
        entry.client_port = client_port_;
        entry.data_port = data_port_;
        entry.comment = comment_;

        servers_id.push_back(entry);
    }

    // Сохранение производится после релиза локера (save_all использует собственную блокировку)
    save_all();

    spdlog::info("Server created with ID {}, client_port={}, data_port={}", gen_id(), client_port_, data_port_);
}

void DataServers::show_id() const {
    std::lock_guard<std::mutex> lock(mtx_);
    spdlog::info("\n=== Logs ===");
    for (const auto& l : servers_id) {
        spdlog::info("ID: {} | Client: {} | Data: {} | Comment: {}", l.id, l.client_port, l.data_port, l.comment);
    }
}

void DataServers::delete_id() {
    show_id();
    spdlog::info("Enter the server ID to delete: ");
    int id;
    std::cin >> id;

    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (auto it = servers_id.begin(); it != servers_id.end(); ++it) {
            if (it->id == id) {
                ports.push_back(it->client_port);
                ports.push_back(it->data_port);
                servers_id.erase(it);
                goto saved;
            }
        }
    }
    spdlog::error("Error: server with ID {} not found!", id);
    return;

saved:
    save_all();
    spdlog::info("Server with ID deleted: {}", id);
}

void DataServers::save_all() {
    std::lock_guard<std::mutex> lock(mtx_);
    {
        std::ofstream outfile(id_file, std::ios::trunc);
        if (!outfile.is_open()) {
            spdlog::error("Error: cannot open {} for writing!", id_file);
        }
        else {
            for (const auto& entry : servers_id) {
                outfile << entry.to_string() << "\n";
            }
        }
    }

    {
        std::ofstream outfile(port_file, std::ios::trunc);
        if (!outfile.is_open()) {
            spdlog::error("Error: cannot open {} for writing!", port_file);
        }
        else {
            for (int port : ports) {
                outfile << port << "\n";
            }
        }
    }

    spdlog::info("Servers and ports state saved.");
}

bool DataServers::authorize_id(uint32_t id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers_id) {
        if (s.id == id) {
            spdlog::info("Authorization successful for ID {}", id);
            return true;
        }
    }
    spdlog::info("Authorization FAILED for ID {}", id);
    return false;
}

std::array<int, 2> DataServers::get_ports_by_id(int search_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers_id) {
        if (s.id == search_id) {
            
            return { s.data_port, s.client_port };
        }
    }
    throw std::runtime_error("ID not found");
}

