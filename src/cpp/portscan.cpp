// Simple Port Scanner in C++
// Build: g++ -std=c++17 -pthread -o portscan portscan.cpp
// Usage: ./portscan <target> <start_port> <end_port> [threads]
// DISCLAIMER: For authorized testing only!

#include <iostream>
#include <string>
#include <thread>
#include <vector>
#include <chrono>
#include <mutex>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>

class SimplePortScanner {
private:
    std::string target;
    int timeout_ms;
    int max_threads;
    std::mutex print_mutex;
    std::vector<int> open_ports;
    
public:
    SimplePortScanner(const std::string& tgt, int timeout = 1000, int threads = 50)
        : target(tgt), timeout_ms(timeout), max_threads(threads) {}
    
    bool scan_port(int port) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) return false;
        
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
        return is_open;
    }
    
    void scan_range(int start_port, int end_port) {
        auto start_time = std::chrono::high_resolution_clock::now();
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
            
            threads.emplace_back([this, thread_start, thread_end]() {
                for (int port = thread_start; port <= thread_end; ++port) {
                    if (scan_port(port)) {
                        std::lock_guard<std::mutex> lock(print_mutex);
                        std::cout << "[+] Port " << port << ": OPEN\n";
                        open_ports.push_back(port);
                    }
                }
            });
        }
        
        for (auto& t : threads) {
            t.join();
        }
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto scan_time = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        
        std::cout << "\n=== Scan Results ===\n";
        std::cout << "Total ports scanned: " << total_ports << "\n";
        std::cout << "Open ports found: " << open_ports.size() << "\n";
        std::cout << "Scan time: " << scan_time.count() << "ms\n";
        
        if (!open_ports.empty()) {
            std::cout << "\n=== Open Ports ===\n";
            for (int port : open_ports) {
                std::cout << "Port " << port << "\n";
            }
        }
    }
    
    std::string get_service_name(int port) {
        switch(port) {
            case 21: return "FTP";
            case 22: return "SSH";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 80: return "HTTP";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 443: return "HTTPS";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 3306: return "MySQL";
            case 1433: return "MSSQL";
            case 6379: return "Redis";
            case 27017: return "MongoDB";
            default: return "Unknown";
        }
    }
};

void print_usage(const std::string& program) {
    std::cout << "Simple Port Scanner in C++\n";
    std::cout << "Usage: " << program << " <target> <start_port> <end_port> [threads]\n\n";
    std::cout << "Arguments:\n";
    std::cout << "  target      - Target IP address or hostname\n";
    std::cout << "  start_port  - Starting port number\n";
    std::cout << "  end_port    - Ending port number\n";
    std::cout << "  threads     - Number of threads (optional, default: 50)\n";
    std::cout << "\nExamples:\n";
    std::cout << "  " << program << " 192.168.1.1 1 1000\n";
    std::cout << "  " << program << " scanme.nmap.org 20 80 100\n";
    std::cout << "  " << program << " 10.0.0.1 443 443\n";
    std::cout << "\nDISCLAIMER: For authorized testing only!\n";
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc > 5) {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string target = argv[1];
    int start_port = std::stoi(argv[2]);
    int end_port = std::stoi(argv[3]);
    int threads = (argc == 5) ? std::stoi(argv[4]) : 50;
    
    // Validate port range
    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        std::cerr << "Error: Invalid port range. Ports must be between 1-65535 and start <= end\n";
        return 1;
    }
    
    // Validate thread count
    if (threads < 1 || threads > 1000) {
        std::cerr << "Error: Thread count must be between 1-1000\n";
        return 1;
    }
    
    SimplePortScanner scanner(target, 1000, threads);
    scanner.scan_range(start_port, end_port);
    
    return 0;
}