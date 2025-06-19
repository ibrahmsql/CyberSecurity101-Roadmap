/*
   Network Security Toolkit in C
   Build: gcc -o netsec network_security.c -lpthread
   Usage: ./netsec [command] [options]
   DISCLAIMER: For authorized testing only!
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_THREADS 100
#define TIMEOUT_SEC 2
#define BUFFER_SIZE 1024

typedef struct {
    char target[256];
    int start_port;
    int end_port;
    int thread_id;
    int total_threads;
} scan_args_t;

typedef struct {
    char host[256];
    char path[512];
    int port;
} url_info_t;

int open_ports[65536];
int open_count = 0;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

// Port scanning functions
int scan_port(const char* target, int port) {
    int sock;
    struct sockaddr_in addr;
    struct timeval timeout;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;
    
    // Set socket timeout
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &addr.sin_addr);
    
    int result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    close(sock);
    
    return (result == 0);
}

void* threaded_scan(void* args) {
    scan_args_t* scan_args = (scan_args_t*)args;
    
    int ports_per_thread = (scan_args->end_port - scan_args->start_port + 1) / scan_args->total_threads;
    int start = scan_args->start_port + (scan_args->thread_id * ports_per_thread);
    int end = (scan_args->thread_id == scan_args->total_threads - 1) ? 
              scan_args->end_port : start + ports_per_thread - 1;
    
    for (int port = start; port <= end; port++) {
        if (scan_port(scan_args->target, port)) {
            pthread_mutex_lock(&print_mutex);
            printf("[+] Port %d: OPEN\n", port);
            open_ports[open_count++] = port;
            pthread_mutex_unlock(&print_mutex);
        }
    }
    
    return NULL;
}

// Service detection
const char* detect_service(int port) {
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

// Banner grabbing
void grab_banner(const char* target, int port) {
    int sock;
    struct sockaddr_in addr;
    char buffer[BUFFER_SIZE];
    struct timeval timeout;
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return;
    
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, target, &addr.sin_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
        memset(buffer, 0, BUFFER_SIZE);
        recv(sock, buffer, BUFFER_SIZE - 1, 0);
        
        if (strlen(buffer) > 0) {
            printf("[+] Banner for port %d: %s", port, buffer);
        }
    }
    
    close(sock);
}

// URL parsing
int parse_url(const char* url, url_info_t* info) {
    char* url_copy = strdup(url);
    char* ptr;
    
    // Default values
    info->port = 80;
    strcpy(info->path, "/");
    
    // Remove protocol
    if (strncmp(url_copy, "http://", 7) == 0) {
        ptr = url_copy + 7;
        info->port = 80;
    } else if (strncmp(url_copy, "https://", 8) == 0) {
        ptr = url_copy + 8;
        info->port = 443;
    } else {
        ptr = url_copy;
    }
    
    // Extract host and path
    char* path_start = strchr(ptr, '/');
    if (path_start) {
        strcpy(info->path, path_start);
        *path_start = '\0';
    }
    
    // Extract port if specified
    char* port_start = strchr(ptr, ':');
    if (port_start) {
        info->port = atoi(port_start + 1);
        *port_start = '\0';
    }
    
    strcpy(info->host, ptr);
    free(url_copy);
    return 1;
}

// HTTP header analysis
void analyze_http_headers(const char* url) {
    url_info_t info;
    if (!parse_url(url, &info)) {
        printf("[-] Invalid URL format\n");
        return;
    }
    
    int sock;
    struct sockaddr_in addr;
    struct hostent* host_entry;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE * 4];
    
    // Resolve hostname
    host_entry = gethostbyname(info.host);
    if (!host_entry) {
        printf("[-] Could not resolve hostname: %s\n", info.host);
        return;
    }
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        printf("[-] Socket creation failed\n");
        return;
    }
    
    addr.sin_family = AF_INET;
    addr.sin_port = htons(info.port);
    addr.sin_addr = *((struct in_addr*)host_entry->h_addr);
    
    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        printf("[-] Connection failed to %s:%d\n", info.host, info.port);
        close(sock);
        return;
    }
    
    // Send HTTP request
    snprintf(request, sizeof(request), 
        "HEAD %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: NetSec-Scanner/1.0\r\n"
        "Connection: close\r\n\r\n", 
        info.path, info.host);
    
    send(sock, request, strlen(request), 0);
    
    // Receive response
    memset(response, 0, sizeof(response));
    recv(sock, response, sizeof(response) - 1, 0);
    
    printf("[+] HTTP Headers Analysis for %s\n", url);
    printf("Response:\n%s\n", response);
    
    // Check for security headers
    const char* security_headers[] = {
        "X-Frame-Options",
        "X-XSS-Protection", 
        "X-Content-Type-Options",
        "Strict-Transport-Security",
        "Content-Security-Policy"
    };
    
    printf("\n[+] Security Headers Check:\n");
    for (int i = 0; i < 5; i++) {
        if (strstr(response, security_headers[i])) {
            printf("[+] %s: Present\n", security_headers[i]);
        } else {
            printf("[-] %s: Missing\n", security_headers[i]);
        }
    }
    
    close(sock);
}

// Subdomain enumeration
void subdomain_enum(const char* domain) {
    const char* subdomains[] = {
        "www", "mail", "ftp", "admin", "test", "dev", "staging", 
        "api", "blog", "shop", "secure", "vpn", "remote"
    };
    
    printf("[+] Subdomain enumeration for %s\n", domain);
    
    for (int i = 0; i < 13; i++) {
        char subdomain[256];
        snprintf(subdomain, sizeof(subdomain), "%s.%s", subdomains[i], domain);
        
        struct hostent* host_entry = gethostbyname(subdomain);
        if (host_entry) {
            printf("[+] Found: %s -> %s\n", subdomain, 
                   inet_ntoa(*((struct in_addr*)host_entry->h_addr)));
        }
    }
}

void print_usage(const char* program) {
    printf("Network Security Scanner\n");
    printf("Usage: %s [command] [options]\n\n", program);
    printf("Commands:\n");
    printf("  portscan <target> <start> <end>    - TCP port scan\n");
    printf("  banner <target> <port>             - Banner grabbing\n");
    printf("  headers <url>                      - HTTP headers analysis\n");
    printf("  subdomain <domain>                 - Subdomain enumeration\n");
    printf("\nExamples:\n");
    printf("  %s portscan 192.168.1.1 1 1000\n", program);
    printf("  %s banner 192.168.1.1 80\n", program);
    printf("  %s headers https://example.com\n", program);
    printf("  %s subdomain example.com\n", program);
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char* command = argv[1];
    
    if (strcmp(command, "portscan") == 0) {
        if (argc != 5) {
            printf("Usage: %s portscan <target> <start_port> <end_port>\n", argv[0]);
            return 1;
        }
        
        const char* target = argv[2];
        int start_port = atoi(argv[3]);
        int end_port = atoi(argv[4]);
        int num_threads = (end_port - start_port > MAX_THREADS) ? MAX_THREADS : (end_port - start_port + 1);
        
        printf("[+] Scanning %s ports %d-%d with %d threads\n", 
               target, start_port, end_port, num_threads);
        
        pthread_t threads[MAX_THREADS];
        scan_args_t args[MAX_THREADS];
        
        clock_t start_time = clock();
        
        for (int i = 0; i < num_threads; i++) {
            strcpy(args[i].target, target);
            args[i].start_port = start_port;
            args[i].end_port = end_port;
            args[i].thread_id = i;
            args[i].total_threads = num_threads;
            
            pthread_create(&threads[i], NULL, threaded_scan, &args[i]);
        }
        
        for (int i = 0; i < num_threads; i++) {
            pthread_join(threads[i], NULL);
        }
        
        clock_t end_time = clock();
        double scan_time = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
        
        printf("\n[+] Scan completed in %.2f seconds\n", scan_time);
        printf("[+] Found %d open ports\n", open_count);
        
        // Service detection for open ports
        if (open_count > 0) {
            printf("\n[+] Service Detection:\n");
            for (int i = 0; i < open_count; i++) {
                printf("Port %d: %s\n", open_ports[i], detect_service(open_ports[i]));
            }
        }
        
    } else if (strcmp(command, "banner") == 0) {
        if (argc != 4) {
            printf("Usage: %s banner <target> <port>\n", argv[0]);
            return 1;
        }
        
        const char* target = argv[2];
        int port = atoi(argv[3]);
        
        printf("[+] Banner grabbing for %s:%d\n", target, port);
        grab_banner(target, port);
        
    } else if (strcmp(command, "headers") == 0) {
        if (argc != 3) {
            printf("Usage: %s headers <url>\n", argv[0]);
            return 1;
        }
        
        analyze_http_headers(argv[2]);
        
    } else if (strcmp(command, "subdomain") == 0) {
        if (argc != 3) {
            printf("Usage: %s subdomain <domain>\n", argv[0]);
            return 1;
        }
        
        subdomain_enum(argv[2]);
        
    } else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[0]);
        return 1;
    }
    
    return 0;
}
