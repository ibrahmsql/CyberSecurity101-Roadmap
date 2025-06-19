/*
 * Simple Port Scanner in C
 * Compile: gcc -o portscan portscan.c -pthread
 * Usage: ./portscan <target> <start_port> <end_port>
 * DISCLAIMER: For authorized testing only!
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>

#define MAX_THREADS 100
#define TIMEOUT_SEC 1

typedef struct {
    char *target;
    int port;
    int *open_ports;
    int *open_count;
    pthread_mutex_t *mutex;
} scan_args_t;

void *scan_port(void *args) {
    scan_args_t *scan_data = (scan_args_t *)args;
    int sockfd;
    struct sockaddr_in target_addr;
    struct hostent *host_entry;
    struct timeval timeout;
    
    // Create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        pthread_exit(NULL);
    }
    
    // Set timeout
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    
    // Setup target address
    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(scan_data->port);
    
    // Convert target to IP address
    if (inet_aton(scan_data->target, &target_addr.sin_addr) == 0) {
        // Try to resolve hostname
        host_entry = gethostbyname(scan_data->target);
        if (host_entry == NULL) {
            close(sockfd);
            pthread_exit(NULL);
        }
        memcpy(&target_addr.sin_addr, host_entry->h_addr_list[0], host_entry->h_length);
    }
    
    // Attempt connection
    if (connect(sockfd, (struct sockaddr *)&target_addr, sizeof(target_addr)) == 0) {
        printf("[+] Port %d/tcp open\n", scan_data->port);
        
        // Add to open ports list
        pthread_mutex_lock(scan_data->mutex);
        scan_data->open_ports[(*scan_data->open_count)++] = scan_data->port;
        pthread_mutex_unlock(scan_data->mutex);
    }
    
    close(sockfd);
    pthread_exit(NULL);
}

void print_usage(char *program_name) {
    printf("Simple Port Scanner in C\n");
    printf("Usage: %s <target> <start_port> <end_port>\n", program_name);
    printf("\n");
    printf("Examples:\n");
    printf("  %s 192.168.1.1 1 1000\n", program_name);
    printf("  %s google.com 80 443\n", program_name);
    printf("  %s localhost 20 25\n", program_name);
    printf("\n");
}

int compare_ints(const void *a, const void *b) {
    return (*(int*)a - *(int*)b);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    char *target = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);
    
    // Validate port range
    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        printf("Error: Invalid port range (1-65535)\n");
        return 1;
    }
    
    printf("[+] Starting port scan on %s\n", target);
    printf("[+] Scanning ports %d-%d\n\n", start_port, end_port);
    
    clock_t start_time = clock();
    
    // Initialize variables
    int total_ports = end_port - start_port + 1;
    int open_ports[total_ports];
    int open_count = 0;
    pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Create thread pool
    pthread_t threads[MAX_THREADS];
    scan_args_t thread_args[MAX_THREADS];
    int active_threads = 0;
    
    // Scan each port
    for (int port = start_port; port <= end_port; port++) {
        // Wait for available thread slot
        if (active_threads >= MAX_THREADS) {
            pthread_join(threads[active_threads % MAX_THREADS], NULL);
            active_threads--;
        }
        
        // Setup thread arguments
        int thread_index = active_threads % MAX_THREADS;
        thread_args[thread_index].target = target;
        thread_args[thread_index].port = port;
        thread_args[thread_index].open_ports = open_ports;
        thread_args[thread_index].open_count = &open_count;
        thread_args[thread_index].mutex = &mutex;
        
        // Create thread
        if (pthread_create(&threads[thread_index], NULL, scan_port, &thread_args[thread_index]) != 0) {
            printf("Error creating thread for port %d\n", port);
            continue;
        }
        
        active_threads++;
    }
    
    // Wait for all remaining threads to complete
    for (int i = 0; i < active_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    clock_t end_time = clock();
    double elapsed = ((double)(end_time - start_time)) / CLOCKS_PER_SEC;
    
    printf("\n[+] Scan completed in %.2f seconds\n", elapsed);
    printf("[+] Found %d open ports\n", open_count);
    
    if (open_count > 0) {
        // Sort open ports
        qsort(open_ports, open_count, sizeof(int), compare_ints);
        
        printf("[+] Open ports: ");
        for (int i = 0; i < open_count; i++) {
            printf("%d", open_ports[i]);
            if (i < open_count - 1) printf(", ");
        }
        printf("\n");
    }
    
    pthread_mutex_destroy(&mutex);
    return 0;
}