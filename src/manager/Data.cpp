#include "manager/Data.h"
// ---------------- Server_struct ----------------
std::string Server_struct::to_string() const {
    nlohmann::json j;
    j["id"] = id;
    j["client_port"] = client_port;
    j["comment"] = comment;
    j["total_traffic"] = total_traffic;
    return j.dump();
}

Server_struct Server_struct::from_string(const std::string& line) {
    Server_struct entry;
    auto j = nlohmann::json::parse(line);

    entry.id = j.value("id", 0);
    entry.client_port = j.value("client_port", 0);
    entry.comment = j.value("comment", std::string("0"));
    entry.total_traffic = j.value("total_traffic", uint64_t{ 0 });

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
    if (!infile) {
        return;
    }

    ports.clear();

    int port;
    while (infile >> port) {
        ports.insert(port);
    }
}

int DataServers::gen_id() {
    int new_id;
    bool exists;
    do {
		// Generate a random 7-digit ID
		// Must be careful, because get_random give uint32_t and if we cast it to int, it can be negative, so we need to take care of that
        new_id = static_cast<int>(get_random(1000000, 9999999));
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

bool DataServers::deleteServerById(uint32_t id)
{ 	
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = servers_id.begin(); it != servers_id.end(); ++it) {
        if (it->id == id) {
            ports.insert(it->client_port);
            servers_id.erase(it);
			save_all();
			return true;
        }
    }
	spdlog::error("Error: server with ID {} not found!", id);
	return false;
}

bool DataServers::updateServerComment(uint32_t id, const std::string& new_comment)
{
    std::lock_guard<std::mutex> lock(mtx_);
	bool found = false;
    for (auto& s : servers_id) {
        if (s.id == id) {
            s.comment = new_comment;
            found = true;
        }
    }
    if (found)
    {
        save_all();
        spdlog::info("Server with ID {} comment updated.", id);
		return true;
    }
    else
    {
		spdlog::error("Error: server with ID {} not found!", id);   
		return false;
    }
}

bool DataServers::updateServerTraffic(uint32_t id, uint64_t total_traffic)
{
    std::lock_guard<std::mutex> lock(mtx_);
    bool found = false;
    for (auto& s : servers_id) {
        if (s.id == id) {
            s.total_traffic = total_traffic;
            found = true;
            break;
        }
    }

    if (found) {
        //save_all();
        return true;
    }

    spdlog::warn("Server {} not found while saving traffic", id);
    return false;
}

bool DataServers::add_id(const std::string comment_) {
    std::lock_guard<std::mutex> lock(mtx_);
    int selected_port = -1;
    int new_id;

    if (ports.size() < 1) {
        spdlog::error("Error: not enough free ports available for a new server!");
        return false;
    }
	
    auto it = ports.begin();
    while (it != ports.end()) {
        int candidate = *it;

        it = ports.erase(it);

        if (is_port_available(candidate)) {
            selected_port = candidate;
            break;
        }
    }
    

    new_id = gen_id();
    Server_struct entry;
    entry.id = new_id;
    entry.client_port = selected_port;
    entry.comment = comment_;

    servers_id.push_back(entry);
    save_all();
    
    spdlog::info("Server created with ID {}, client_port={}", new_id, selected_port);

    return true;
}

void DataServers::save_all() {
    std::ofstream outfile_id(id_file, std::ios::trunc);
    if (!outfile_id.is_open()) {
        spdlog::error("Error: cannot open {} for writing!", id_file);
    }
    else {
        for (const auto& entry : servers_id) {
            outfile_id << entry.to_string() << "\n";
        }
    }


    std::ofstream outfile_port(port_file, std::ios::trunc);
    if (!outfile_port.is_open()) {
        spdlog::error("Error: cannot open {} for writing!", port_file);
    }
    else {
        for (int port : ports) {
            outfile_port << port << "\n";
        }
    }
    spdlog::info("Servers and ports state saved.");
}

bool DataServers::authorize_id(uint32_t id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers_id) {
        if (s.id == id) {
            return true;
        }
    }
    return false;
}

int DataServers::get_ports_by_id(int search_id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers_id) {
        if (s.id == search_id) {
            
            return s.client_port;
        }
    }
    throw std::runtime_error("ID not found");
}

std::vector<Server_struct> DataServers::get_servers()  {
	std::lock_guard<std::mutex> lock(mtx_);
	return servers_id;
}

bool DataServers::add_ports(int first, int second) {
    bool changed = false;
    int start = first;
    int end = (second == 0) ? first : second;
    if (start > end) std::swap(start, end);


    if (start <= 1024 || end > 65535) {
        spdlog::warn("Range {}-{} is out of valid bounds", start, end);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mtx_);
        for (int i = start; i <= end; ++i) {

            auto result = ports.insert(i);
            if (result.second) {
                changed = true;
            }
            else {
                spdlog::debug("Port {} already exists in the pool", i);
            }
        }


        if (changed) {
            save_all();
            if (start == end) {
                spdlog::info("Port {} added to the free pool.", start);
            }
            else {
                spdlog::info("Ports from {} to {} added to the free pool.", start, end);
            }
        }
    }
    return true;
}

bool DataServers::delete_port(int first, int second) {
    int start = first;
    int end = (second == 0) ? first : second;
    if (start > end) std::swap(start, end);

    std::lock_guard<std::mutex> lock(mtx_);

    size_t size_before = ports.size();

    if (start == end) {
        ports.erase(start);
    }
    else {
        auto it_start = ports.lower_bound(start);
        auto it_end = ports.upper_bound(end);
        ports.erase(it_start, it_end);
    }

    if (ports.size() != size_before) {
		save_all();
        spdlog::info("Ports from {} to {} removed from pool.", start, end);
        return true;
    }

	spdlog::warn("No ports from {} to {} were found in the pool.", start, end);
    return false; 
}

bool DataServers::is_port_available(int port) {
    asio::io_context ioc; 
    asio::ip::tcp::acceptor acceptor(ioc);
    asio::error_code ec;

    acceptor.open(asio::ip::tcp::v4(), ec);
    if (ec) return false;

    acceptor.bind({ asio::ip::tcp::v4(), static_cast<unsigned short>(port) }, ec);

    return !ec;
}

std::string DataServers::get_port_pool() const {
    std::lock_guard<std::mutex> lock(mtx_);

    nlohmann::json j;

    if (ports.empty()) {
        j["status"] = "empty";
        j["ranges"] = "";
        return j.dump();
    }

    std::string ranges_str;
    int start = *ports.begin();
    int last = start;

    auto add_range = [&](int s, int l) {
        if (!ranges_str.empty()) ranges_str += ", ";
        if (s == l) ranges_str += std::to_string(s);
        else ranges_str += std::to_string(s) + "-" + std::to_string(l);
        };

    for (auto it = std::next(ports.begin()); it != ports.end(); ++it) {
        if (*it != last + 1) {
            add_range(start, last);
            start = *it;
        }
        last = *it;
    }
    add_range(start, last);

    j["status"] = "success";
    j["count"] = ports.size();
    j["ranges"] = ranges_str;

    return j.dump();
}

uint32_t get_random(unsigned int min, unsigned int max) {
    if (min > max) return min;

    unsigned int random_val;

    if (RAND_bytes(reinterpret_cast<unsigned char*>(&random_val), sizeof(random_val)) != 1) {
        throw std::runtime_error("OpenSSL: Error generating random bytes, we will fallback to std::rand()");

        random_val = static_cast<unsigned int>(std::rand());
    }

    unsigned int range = max - min + 1;

    return min + (static_cast<uint32_t>(random_val % range));
}

uint64_t DataServers::get_total_traffic_by_id(uint32_t id) const {
    std::lock_guard<std::mutex> lock(mtx_);
    for (const auto& s : servers_id) {
        if (s.id == id) {
            return s.total_traffic;
        }
    }
    spdlog::warn("Server {} not found while getting total traffic", id);
    return 0;
}