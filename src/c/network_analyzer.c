/*
   Advanced Network Analysis Tool
   Build: gcc -o netanalyzer network_analyzer.c -lpcap
   Usage: sudo ./netanalyzer [command] [options]
   Requires libpcap-dev installed.
   DISCLAIMER: For authorized testing only!
*/

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 65535
#define FILTER_SIZE 256

typedef struct {
    unsigned long total_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long other_packets;
    unsigned long total_bytes;
    time_t start_time;
} packet_stats_t;

packet_stats_t stats = {0};
int verbose_mode = 0;
int capture_running = 1;

void signal_handler(int sig) {
    capture_running = 0;
    printf("\n[+] Capture stopped by user\n");
}

void print_packet_stats() {
    time_t current_time = time(NULL);
    double duration = difftime(current_time, stats.start_time);
    
    printf("\n=== Packet Capture Statistics ===\n");
    printf("Capture Duration: %.0f seconds\n", duration);
    printf("Total Packets: %lu\n", stats.total_packets);
    printf("TCP Packets: %lu (%.1f%%)\n", stats.tcp_packets, 
           (stats.total_packets > 0) ? (stats.tcp_packets * 100.0 / stats.total_packets) : 0);
    printf("UDP Packets: %lu (%.1f%%)\n", stats.udp_packets,
           (stats.total_packets > 0) ? (stats.udp_packets * 100.0 / stats.total_packets) : 0);
    printf("ICMP Packets: %lu (%.1f%%)\n", stats.icmp_packets,
           (stats.total_packets > 0) ? (stats.icmp_packets * 100.0 / stats.total_packets) : 0);
    printf("Other Packets: %lu (%.1f%%)\n", stats.other_packets,
           (stats.total_packets > 0) ? (stats.other_packets * 100.0 / stats.total_packets) : 0);
    printf("Total Bytes: %lu\n", stats.total_bytes);
    if (duration > 0) {
        printf("Average PPS: %.1f\n", stats.total_packets / duration);
        printf("Average BPS: %.1f\n", stats.total_bytes / duration);
    }
}

void analyze_tcp_packet(const u_char *packet, int packet_len) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ihl * 4));
    
    if (verbose_mode) {
        printf("[TCP] %s:%d -> %s:%d ",
               inet_ntoa(*(struct in_addr*)&ip_header->saddr), ntohs(tcp_header->source),
               inet_ntoa(*(struct in_addr*)&ip_header->daddr), ntohs(tcp_header->dest));
        
        printf("Flags: ");
        if (tcp_header->syn) printf("SYN ");
        if (tcp_header->ack) printf("ACK ");
        if (tcp_header->fin) printf("FIN ");
        if (tcp_header->rst) printf("RST ");
        if (tcp_header->psh) printf("PSH ");
        if (tcp_header->urg) printf("URG ");
        printf("Len: %d\n", packet_len);
    }
    
    stats.tcp_packets++;
}

void analyze_udp_packet(const u_char *packet, int packet_len) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    struct udphdr *udp_header = (struct udphdr *)(packet + sizeof(struct ethhdr) + (ip_header->ihl * 4));
    
    if (verbose_mode) {
        printf("[UDP] %s:%d -> %s:%d Len: %d\n",
               inet_ntoa(*(struct in_addr*)&ip_header->saddr), ntohs(udp_header->source),
               inet_ntoa(*(struct in_addr*)&ip_header->daddr), ntohs(udp_header->dest),
               packet_len);
    }
    
    stats.udp_packets++;
}

void analyze_icmp_packet(const u_char *packet, int packet_len) {
    struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    if (verbose_mode) {
        printf("[ICMP] %s -> %s Len: %d\n",
               inet_ntoa(*(struct in_addr*)&ip_header->saddr),
               inet_ntoa(*(struct in_addr*)&ip_header->daddr),
               packet_len);
    }
    
    stats.icmp_packets++;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *hdr, const u_char *packet) {
    if (!capture_running) return;
    
    stats.total_packets++;
    stats.total_bytes += hdr->len;
    
    struct ethhdr *eth_header = (struct ethhdr *)packet;
    
    if (ntohs(eth_header->h_proto) == ETH_P_IP) {
        struct iphdr *ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));
        
        switch (ip_header->protocol) {
            case IPPROTO_TCP:
                analyze_tcp_packet(packet, hdr->len);
                break;
            case IPPROTO_UDP:
                analyze_udp_packet(packet, hdr->len);
                break;
            case IPPROTO_ICMP:
                analyze_icmp_packet(packet, hdr->len);
                break;
            default:
                stats.other_packets++;
                if (verbose_mode) {
                    printf("[OTHER] Protocol: %d Len: %d\n", ip_header->protocol, hdr->len);
                }
                break;
        }
    } else {
        stats.other_packets++;
        if (verbose_mode) {
            printf("[NON-IP] EtherType: 0x%04x Len: %d\n", ntohs(eth_header->h_proto), hdr->len);
        }
    }
    
    // Print stats every 1000 packets
    if (stats.total_packets % 1000 == 0) {
        printf("\r[+] Captured %lu packets...", stats.total_packets);
        fflush(stdout);
    }
}

void list_interfaces() {
    pcap_if_t *interfaces, *temp;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&interfaces, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return;
    }
    
    printf("Available network interfaces:\n");
    for (temp = interfaces; temp; temp = temp->next) {
        printf("  %s", temp->name);
        if (temp->description) {
            printf(" (%s)", temp->description);
        }
        printf("\n");
    }
    
    pcap_freealldevs(interfaces);
}

void capture_packets(const char *interface, const char *filter_exp, int packet_count) {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 net, mask;
    
    // Get network info
    if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Warning: %s\n", errbuf);
        net = 0;
        mask = 0;
    }
    
    // Open interface
    handle = pcap_open_live(interface, MAX_PACKET_SIZE, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return;
    }
    
    // Compile and apply filter
    if (filter_exp && strlen(filter_exp) > 0) {
        if (pcap_compile(handle, &filter, filter_exp, 0, net) == -1) {
            fprintf(stderr, "Filter compilation failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        
        if (pcap_setfilter(handle, &filter) == -1) {
            fprintf(stderr, "Filter application failed: %s\n", pcap_geterr(handle));
            pcap_close(handle);
            return;
        }
        
        printf("[+] Applied filter: %s\n", filter_exp);
    }
    
    printf("[+] Starting packet capture on %s\n", interface);
    printf("[+] Press Ctrl+C to stop\n");
    
    stats.start_time = time(NULL);
    signal(SIGINT, signal_handler);
    
    // Start capture
    pcap_loop(handle, packet_count, packet_handler, NULL);
    
    print_packet_stats();
    pcap_close(handle);
}

void print_usage(const char *program) {
    printf("Advanced Network Analysis Tool\n");
    printf("Usage: %s [command] [options]\n\n", program);
    printf("Commands:\n");
    printf("  capture <interface> [filter] [count] - Capture and analyze packets\n");
    printf("  list                                  - List available interfaces\n");
    printf("\nOptions:\n");
    printf("  -v                                    - Verbose mode\n");
    printf("\nFilter Examples:\n");
    printf("  'tcp port 80'                        - HTTP traffic\n");
    printf("  'udp port 53'                        - DNS traffic\n");
    printf("  'host 192.168.1.1'                   - Traffic to/from specific host\n");
    printf("  'tcp and port 22'                    - SSH traffic\n");
    printf("\nExamples:\n");
    printf("  sudo %s list\n", program);
    printf("  sudo %s capture eth0\n", program);
    printf("  sudo %s capture eth0 'tcp port 80' 100\n", program);
    printf("  sudo %s -v capture wlan0 'icmp'\n", program);
}

int main(int argc, char *argv[]) {
    int opt;
    
    // Parse command line options
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose_mode = 1;
                break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // Adjust argc and argv after option parsing
    argc -= optind;
    argv += optind;
    
    if (argc < 1) {
        print_usage(argv[-optind]);
        return 1;
    }
    
    const char *command = argv[0];
    
    if (strcmp(command, "list") == 0) {
        list_interfaces();
    } else if (strcmp(command, "capture") == 0) {
        if (argc < 2) {
            printf("Usage: capture <interface> [filter] [count]\n");
            return 1;
        }
        
        const char *interface = argv[1];
        const char *filter = (argc > 2) ? argv[2] : NULL;
        int count = (argc > 3) ? atoi(argv[3]) : 0; // 0 means capture indefinitely
        
        if (verbose_mode) {
            printf("[+] Verbose mode enabled\n");
        }
        
        capture_packets(interface, filter, count);
    } else {
        printf("Unknown command: %s\n", command);
        print_usage(argv[-optind]);
        return 1;
    }
    
    return 0;
}
