// Network Security Toolkit in C++
// Build: g++ -std=c++17 -pthread -o netsec network_security.cpp
// Usage: ./netsec [command] [options]
// Requires: C++17, pthread support

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <map>
#include <sstream>
#include <algorithm>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <cstring>

struct ScanResult {
    int port;
    bool is_open;
    std::string service;
    std::string banner;
    
    ScanResult(int p, bool open, const std::string& svc, const std::string& bnr = "")
        : port(p), is_open(open), service(svc), banner(bnr) {}
};

struct ScanStats {
    int total_ports;
    int open_ports;
    std::chrono::milliseconds scan_time;
    
    ScanStats(int total, int open, std::chrono::milliseconds time)
        : total_ports(total), open_ports(open), scan_time(time) {}
};

class NetworkScanner {
private:
    std::string target;
    int timeout_ms;
    int max_threads;
    std::mutex result_mutex;
    
    std::map<int, std::string> service_map = {
        {21, "FTP"}, {22, "SSH"}, {23, "Telnet"}, {25, "SMTP"},
        {53, "DNS"}, {80, "HTTP"}, {110, "POP3"}, {143, "IMAP"},
        {443, "HTTPS"}, {993, "IMAPS"}, {995, "POP3S"}, {3389, "RDP"},
        {5432, "PostgreSQL"}, {3306, "MySQL"}, {1433, "MSSQL"},
        {6379, "Redis"}, {27017, "MongoDB"}
    };
    
public:
    NetworkScanner(const std::string& tgt, int timeout = 2000, int threads = 50)
        : target(tgt), timeout_ms(timeout), max_threads(threads) {}
    
    std::string detect_service(int port) {
        auto it = service_map.find(port);
        return (it != service_map.end()) ? it->second : "Unknown";
    }
    
    std::string grab_banner(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return "";
        
        // Set socket timeout
        struct timeval tv;
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        std::string banner;
        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            char buffer[1024] = {0};
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes > 0) {
                banner = std::string(buffer, bytes);
                // Remove newlines and trim
                banner.erase(std::remove(banner.begin(), banner.end(), '\n'), banner.end());
                banner.erase(std::remove(banner.begin(), banner.end(), '\r'), banner.end());
            }
        }
        close(sock);
        return banner;
    }
    
    ScanResult scan_port(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            return ScanResult(port, false, detect_service(port));
        }
        
        // Set non-blocking
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);
        
        bool is_open = false;
        connect(sock, (struct sockaddr*)&addr, sizeof(addr));
        
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);
        
        struct timeval timeout;
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        
        if (select(sock + 1, NULL, &write_fds, NULL, &timeout) > 0) {
            int error = 0;
            socklen_t len = sizeof(error);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &len);
            is_open = (error == 0);
        }
        
        close(sock);
        
        std::string service = detect_service(port);
        std::string banner;
        if (is_open) {
            banner = grab_banner(port);
        }
        
        return ScanResult(port, is_open, service, banner);
    }
    
    std::pair<std::vector<ScanResult>, ScanStats> scan_range(int start_port, int end_port) {
        auto start_time = std::chrono::high_resolution_clock::now();
        std::vector<ScanResult> results;
        std::vector<std::thread> threads;
        
        int total_ports = end_port - start_port + 1;
        std::cout << "[+] Scanning " << target << " ports " << start_port << "-" << end_port 
                  << " with " << max_threads << " threads\n";
        
        // Divide ports among threads
        int ports_per_thread = total_ports / max_threads;
        int remaining_ports = total_ports % max_threads;
        
        int current_port = start_port;
        for (int i = 0; i < max_threads; ++i) {
            int thread_ports = ports_per_thread + (i < remaining_ports ? 1 : 0);
            int thread_start = current_port;
            int thread_end = current_port + thread_ports - 1;
            current_port += thread_ports;
            
            threads.emplace_back([this, thread_start, thread_end, &results]() {
                for (int port = thread_start; port <= thread_end; ++port) {
                    ScanResult result = scan_port(port);
                    
                    std::lock_guard<std::mutex> lock(result_mutex);
                    results.push_back(result);
                    
                    if (result.is_open) {
                        std::cout << "[+] Port " << result.port << ": OPEN (" << result.service << ")\n";
                        if (!result.banner.empty()) {
                            std::cout << "    Banner: " << result.banner << "\n";
                        }
                    }
                }
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto scan_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        int open_ports = std::count_if(results.begin(), results.end(), 
                                     [](const ScanResult& r) { return r.is_open; });
        
        return {results, ScanStats(total_ports, open_ports, scan_time)};
    }
};

class SubdomainScanner {
private:
    std::string domain;
    
public:
    SubdomainScanner(const std::string& dom) : domain(dom) {}
    
    void enumerate_subdomains() {
        std::vector<std::string> subdomains = {
            "www", "mail", "ftp", "admin", "test", "dev", "staging",
            "api", "blog", "shop", "secure", "vpn", "remote", "portal",
            "app", "mobile", "m", "support", "help", "docs"
        };
        
        std::cout << "[+] Subdomain enumeration for " << domain << "\n";
        
        for (const auto& subdomain : subdomains) {
            std::string full_domain = subdomain + "." + domain;
            
            struct hostent* host_entry = gethostbyname(full_domain.c_str());
            if (host_entry != nullptr) {
                char* ip = inet_ntoa(*((struct in_addr*)host_entry->h_addr_list[0]));
                std::cout << "[+] Found: " << full_domain << " -> " << ip << "\n";
            }
        }
    }
};

void print_usage(const std::string& program) {
    std::cout << "Network Security Toolkit in C++\n";
    std::cout << "Usage: " << program << " [command] [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  portscan <target> <start> <end> [threads] - TCP port scan\n";
    std::cout << "  banner <target> <port>                    - Banner grabbing\n";
    std::cout << "  subdomain <domain>                        - Subdomain enumeration\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program << " portscan 192.168.1.1 1 1000\n";
    std::cout << "  " << program << " portscan 192.168.1.1 1 1000 100\n";
    std::cout << "  " << program << " banner 192.168.1.1 80\n";
    std::cout << "  " << program << " subdomain example.com\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string command = argv[1];
    
    if (command == "portscan") {
        if (argc < 5) {
            std::cerr << "Usage: " << argv[0] << " portscan <target> <start-port> <end-port> [threads]\n";
            return 1;
        }
        
        std::string target = argv[2];
        int start_port = std::stoi(argv[3]);
        int end_port = std::stoi(argv[4]);
        int threads = (argc > 5) ? std::stoi(argv[5]) : 50;
        
        NetworkScanner scanner(target, 2000, threads);
        auto [results, stats] = scanner.scan_range(start_port, end_port);
        
        std::cout << "\n=== Scan Results ===\n";
        std::cout << "Total ports scanned: " << stats.total_ports << "\n";
        std::cout << "Open ports found: " << stats.open_ports << "\n";
        std::cout << "Scan time: " << stats.scan_time.count() << "ms\n";
        
        if (stats.open_ports > 0) {
            std::cout << "\n=== Open Ports ===\n";
            for (const auto& result : results) {
                if (result.is_open) {
                    std::string banner_info = result.banner.empty() ? "no banner" : "with banner";
                    std::cout << "Port " << result.port << ": " << result.service 
                              << " (" << banner_info << ")\n";
                }
            }
        }
    }
    else if (command == "banner") {
        if (argc != 4) {
            std::cerr << "Usage: " << argv[0] << " banner <target> <port>\n";
            return 1;
        }
        
        std::string target = argv[2];
        int port = std::stoi(argv[3]);
        
        NetworkScanner scanner(target);
        std::cout << "[+] Banner grabbing for " << target << ":" << port << "\n";
        
        std::string banner = scanner.grab_banner(port);
        if (!banner.empty()) {
            std::cout << "[+] Banner: " << banner << "\n";
        } else {
            std::cout << "[-] No banner received\n";
        }
    }
    else if (command == "subdomain") {
        if (argc != 3) {
            std::cerr << "Usage: " << argv[0] << " subdomain <domain>\n";
            return 1;
        }
        
        std::string domain = argv[2];
        SubdomainScanner scanner(domain);
        scanner.enumerate_subdomains();
    }
    else {
        std::cerr << "Unknown command: " << command << "\n";
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
