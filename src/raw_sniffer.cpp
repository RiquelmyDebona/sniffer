#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <signal.h>
#include <assert.h>
#include <unordered_map>
#include <optional>

#define FILTER_ALL   0
#define FILTER_UDP   1
#define FILTER_TCP   2
#define FILTER_ICMP  3
#define FILTER_HTTP  4
#define IP_MODE_BOTH 0
#define IP_MODE_V4   1
#define IP_MODE_V6   2

typedef unsigned long Ip;
typedef std::optional<uint32_t> ExpectedSeq;
typedef std::unordered_map<Ip, std::unordered_map<Ip, ExpectedSeq>> IpTable;

//Global variables to track packet statistics
int tcp = 0, icmp = 0, igmp = 0, udp = 0, http = 0, others = 0, total = 0;
int ipv4_packets = 0, ipv6_packets = 0;
FILE *logsniff_ipv4, *logsniff_ipv6; //Log files for IPv4 and IPv6
IpTable ipTable; //Table to track expected TCP sequences

//Functions Prototypes
void INThandler(int sig);
FILE* get_log_file(int is_ipv6);
void ethernet_header(unsigned char* Buffer, int Size, int is_ipv6);
void ip_header(unsigned char* Buffer, int Size, int is_ipv6);
bool http_packet(unsigned char* Buffer, int Size, int is_ipv6);
void icmp_packet(unsigned char* Buffer, int Size, int is_ipv6);
void checkAckSeq(struct tcphdr *tcph, void *ip_header_ptr, int is_ipv6);
void tcp_packet(unsigned char* Buffer, int Size, bool http_only, int filter, int is_ipv6);
void udp_packet(unsigned char *Buffer, int Size, int is_ipv6);
void packetCounter(unsigned char* buffer, int size, int filter, int ip_mode);
void print_usage(char **argv);

//Signal handler for Ctrl+C (shows statistics before exiting)
void INThandler(int sig) {
    char c;
    signal(sig, SIG_IGN);
    printf("\nOUCH, did you hit Ctrl-C?\nDo you really want to quit? [y/n] ");
    c = getchar();
    if (c == 'y' || c == 'Y') {
        float ipv4_percent = (total > 0) ? (ipv4_packets * 100.0 / total) : 0;
        float ipv6_percent = (total > 0) ? (ipv6_packets * 100.0 / total) : 0;
        
        printf("\n=== Estatísticas Finais ===\n");
        printf("IPv4: %d (%.2f%%)\n", ipv4_packets, ipv4_percent);
        printf("IPv6: %d (%.2f%%)\n", ipv6_packets, ipv6_percent);
        printf("TCP: %d   UDP: %d   ICMP: %d   HTTP: %d   IGMP: %d   Others: %d   Total: %d\n", 
               tcp, udp, icmp, http, igmp, others, total);
        
        fclose(logsniff_ipv4);
        fclose(logsniff_ipv6);
        exit(0);
    }
    signal(SIGINT, INThandler);
    while (getchar() != '\n'); // Limpa buffer de entrada
}

//Returns appropriate log file based on IP version
FILE* get_log_file(int is_ipv6) {
    return is_ipv6 ? logsniff_ipv6 : logsniff_ipv4;
}

//Prints Ethernet header details to log
void ethernet_header(unsigned char* Buffer, int Size, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    struct ethhdr *eth = (struct ethhdr *)Buffer;
    fprintf(logsniff, "\nEthernet Header\n");
    fprintf(logsniff, "   |-Destination MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
            eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], 
            eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
    fprintf(logsniff, "   |-Source MAC: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", 
            eth->h_source[0], eth->h_source[1], eth->h_source[2], 
            eth->h_source[3], eth->h_source[4], eth->h_source[5]);
    fprintf(logsniff, "   |-Protocol: %s (0x%04X)\n", 
            is_ipv6 ? "IPv6" : "IPv4", ntohs(eth->h_proto));
}

//Prints IP header details (supports both IPv4 and IPv6)
void ip_header(unsigned char* Buffer, int Size, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    ethernet_header(Buffer, Size, is_ipv6);

    if (!is_ipv6) {
        struct iphdr *iph = (struct iphdr *)(Buffer + sizeof(struct ethhdr));
        fprintf(logsniff, "\nIPv4 Header\n");
        fprintf(logsniff, "   |-Version: %d\n", iph->version);
        fprintf(logsniff, "   |-IHL: %d DWORDS\n", iph->ihl);
        fprintf(logsniff, "   |-TTL: %d\n", iph->ttl);
        fprintf(logsniff, "   |-Protocol: %d\n", iph->protocol);
        fprintf(logsniff, "   |-Source IP: %s\n", inet_ntoa(*(struct in_addr*)&iph->saddr));
        fprintf(logsniff, "   |-Destination IP: %s\n", inet_ntoa(*(struct in_addr*)&iph->daddr));
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(Buffer + sizeof(struct ethhdr));
        char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6h->ip6_src, src, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6h->ip6_dst, dst, INET6_ADDRSTRLEN);
        
        fprintf(logsniff, "\nIPv6 Header\n");
        fprintf(logsniff, "   |-Version: %d\n", (ip6h->ip6_vfc >> 4));
        fprintf(logsniff, "   |-Next Header: %d\n", ip6h->ip6_nxt);
        fprintf(logsniff, "   |-Hop Limit: %d\n", ip6h->ip6_hops);
        fprintf(logsniff, "   |-Source IP: %s\n", src);
        fprintf(logsniff, "   |-Destination IP: %s\n", dst);
    }
}

//Detects HTTP packets by checking payload for HTTP methods
bool http_packet(unsigned char* Buffer, int Size, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    int ip_header_len = is_ipv6 ? sizeof(struct ip6_hdr) : ((struct iphdr*)(Buffer + sizeof(struct ethhdr)))->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr*)(Buffer + sizeof(struct ethhdr) + ip_header_len);
    int header_size = sizeof(struct ethhdr) + ip_header_len + tcph->doff * 4;
    int payload_size = Size - header_size;
    
    if (payload_size <= 0) {
        fprintf(logsniff, "\nHTTP Packet (Header Only)\n");
        return false;
    }

    char *payload = (char*)(Buffer + header_size);
    bool is_http = false;
    const char *http_methods[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "HTTP/"};
    
    for (const char *method : http_methods) {
        if (strncmp(payload, method, strlen(method)) == 0) {
            is_http = true;
            break;
        }
    }

    if (!is_http) return false;

    http++;
    fprintf(logsniff, "\nHTTP Packet\n");
    // ... (restante da análise HTTP igual ao original)
    return true;
}

//Verifies TCP sequence numbers against expected values
void checkAckSeq(struct tcphdr *tcph, void *ip_header_ptr, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
    Ip sourceIp, destIp;

    if (!is_ipv6) {
        struct iphdr *iph = (struct iphdr *)ip_header_ptr;
        sourceIp = iph->saddr;
        destIp = iph->daddr;
        inet_ntop(AF_INET, &iph->saddr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &iph->daddr, dst_ip, INET_ADDRSTRLEN);
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)ip_header_ptr;
        sourceIp = *((Ip*)&ip6h->ip6_src);
        destIp = *((Ip*)&ip6h->ip6_dst);
        inet_ntop(AF_INET6, &ip6h->ip6_src, src_ip, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ip6h->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
    }

    if (ipTable[destIp].count(sourceIp) && ipTable[destIp][sourceIp].has_value()) {
        uint32_t expected = ipTable[destIp][sourceIp].value();
        uint32_t received = ntohl(tcph->seq);
        
        if (expected != received) {
            fprintf(logsniff, "\nTCP Sequence Error: %s -> %s\n", src_ip, dst_ip);
            fprintf(logsniff, "   Expected SEQ: %u, Received SEQ: %u\n", expected, received);
        }
    }
    ipTable[sourceIp][destIp] = ntohl(tcph->ack_seq);
}

//Handles ICMP/ICMPv6 packets and logs details
void icmp_packet(unsigned char* Buffer, int Size, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);

    if (!is_ipv6) {
        // IPv4 ICMP
        struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
        struct icmphdr *icmph = (struct icmphdr*)(Buffer + sizeof(struct ethhdr) + (iph->ihl * 4));

        fprintf(logsniff, "\n***********************ICMPv4 Packet***********************\n");
        ip_header(Buffer, Size, is_ipv6);

        fprintf(logsniff, "   |-Type: %d", icmph->type);
        if (icmph->type == ICMP_ECHOREPLY) fprintf(logsniff, " (Echo Reply)");
        else if (icmph->type == ICMP_ECHO) fprintf(logsniff, " (Echo Request)");
        fprintf(logsniff, "\n   |-Code: %d\n", icmph->code);
        fprintf(logsniff, "   |-Checksum: %d\n", ntohs(icmph->checksum));
    } else {
        // IPv6 ICMPv6
        struct ip6_hdr *ip6h = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
        struct icmp6_hdr *icmp6h = (struct icmp6_hdr*)(Buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));

        fprintf(logsniff, "\n***********************ICMPv6 Packet***********************\n");
        ip_header(Buffer, Size, is_ipv6);

        fprintf(logsniff, "   |-Type: %d", icmp6h->icmp6_type);
        if (icmp6h->icmp6_type == ICMP6_ECHO_REQUEST) fprintf(logsniff, " (Echo Request)");
        else if (icmp6h->icmp6_type == ICMP6_ECHO_REPLY) fprintf(logsniff, " (Echo Reply)");
        fprintf(logsniff, "\n   |-Code: %d\n", icmp6h->icmp6_code);
        fprintf(logsniff, "   |-Checksum: %d\n", ntohs(icmp6h->icmp6_cksum));
    }
}

//Processes TCP packets (includes HTTP detection and sequence checking)
void tcp_packet(unsigned char* Buffer, int Size, bool http_only, int filter, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    struct tcphdr *tcph;
    int header_size;

    if (!is_ipv6) {
        struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
        tcph = (struct tcphdr*)(Buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
        header_size = sizeof(struct ethhdr) + (iph->ihl * 4) + (tcph->doff * 4);
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
        tcph = (struct tcphdr*)(Buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
        header_size = sizeof(struct ethhdr) + sizeof(struct ip6_hdr) + (tcph->doff * 4);
    }

    // Check HTTP/HTTPS
    if ((ntohs(tcph->dest) == 80 || ntohs(tcph->source) == 80 || ntohs(tcph->dest) == 443 || ntohs(tcph->source) == 443)) {
        if (http_packet(Buffer, Size, is_ipv6) && filter == FILTER_HTTP) return;
    }

    if (!http_only) {
        fprintf(logsniff, "\n***********************TCP Packet (%s)***********************\n",
                is_ipv6 ? "IPv6" : "IPv4");
        ip_header(Buffer, Size, is_ipv6);

        fprintf(logsniff, "   |-Source Port: %u\n", ntohs(tcph->source));
        fprintf(logsniff, "   |-Destination Port: %u\n", ntohs(tcph->dest));
        fprintf(logsniff, "   |-Sequence Number: %u\n", ntohl(tcph->seq));
        fprintf(logsniff, "   |-Ack Number: %u\n", ntohl(tcph->ack_seq));
        fprintf(logsniff, "   |-Flags: %s%s%s%s%s%s\n",
                tcph->urg ? "URG " : "", tcph->ack ? "ACK " : "",
                tcph->psh ? "PSH " : "", tcph->rst ? "RST " : "",
                tcph->syn ? "SYN " : "", tcph->fin ? "FIN " : "");

        // Payload (first 64 bytes)
        int payload_size = Size - header_size;
        if (payload_size > 0) {
            fprintf(logsniff, "Payload (%d bytes):\n", payload_size);
            int display_size = payload_size > 64 ? 64 : payload_size;
            for (int i = 0; i < display_size; i++) {
                fprintf(logsniff, "%02X ", Buffer[header_size + i]);
                if ((i+1) % 16 == 0) fprintf(logsniff, "\n");
            }
            if (payload_size > 64) fprintf(logsniff, "\n[Truncated to 64 bytes]");
            fprintf(logsniff, "\n");
        }
    }
}


//Processes UDP packets (includes DNS detection)
void udp_packet(unsigned char* Buffer, int Size, int is_ipv6) {
    FILE* logsniff = get_log_file(is_ipv6);
    struct udphdr *udph;
    
    if (!is_ipv6) {
        struct iphdr *iph = (struct iphdr*)(Buffer + sizeof(struct ethhdr));
        udph = (struct udphdr*)(Buffer + sizeof(struct ethhdr) + (iph->ihl * 4));
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr*)(Buffer + sizeof(struct ethhdr));
        udph = (struct udphdr*)(Buffer + sizeof(struct ethhdr) + sizeof(struct ip6_hdr));
    }

    fprintf(logsniff, "\n***********************UDP Packet (%s)***********************\n",
            is_ipv6 ? "IPv6" : "IPv4");
    ip_header(Buffer, Size, is_ipv6);

    fprintf(logsniff, "   |-Source Port: %u\n", ntohs(udph->source));
    fprintf(logsniff, "   |-Destination Port: %u\n", ntohs(udph->dest));
    fprintf(logsniff, "   |-Length: %u\n", ntohs(udph->len));
    fprintf(logsniff, "   |-Checksum: %u\n", ntohs(udph->check));

    // DNS detection (port 53)
    if (ntohs(udph->source) == 53 || ntohs(udph->dest) == 53) {
        fprintf(logsniff, "   |-Protocol: DNS\n");
    }
}

//Main packet processing function - routes packets to appropriate handlers
void packetCounter(unsigned char* buffer, int size, int filter, int ip_mode) {
    struct ethhdr *eth = (struct ethhdr*)buffer;
    int is_ipv6 = (ntohs(eth->h_proto) == ETH_P_IPV6);

    // Skip packets based on IP mode
    if ((ip_mode == IP_MODE_V4 && is_ipv6) || (ip_mode == IP_MODE_V6 && !is_ipv6)) {
        return;
    }

    is_ipv6 ? ipv6_packets++ : ipv4_packets++;
    total++;

    if (!is_ipv6) {
        struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
        switch (iph->protocol) {
            case IPPROTO_ICMP:
                icmp++;
                if (filter == FILTER_ICMP || filter == FILTER_ALL)
                    icmp_packet(buffer, size, is_ipv6);
                break;
            case IPPROTO_TCP:
                tcp++;
                if (filter == FILTER_TCP || filter == FILTER_ALL || filter == FILTER_HTTP)
                    tcp_packet(buffer, size, (filter == FILTER_HTTP), filter, is_ipv6);
                break;
            case IPPROTO_UDP:
                udp++;
                if (filter == FILTER_UDP || filter == FILTER_ALL)
                    udp_packet(buffer, size, is_ipv6);
                break;
            case IPPROTO_IGMP:
                igmp++;
                break;
            default:
                others++;
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
        switch (ip6h->ip6_nxt) {
            case IPPROTO_ICMPV6:
                icmp++;
                if (filter == FILTER_ICMP || filter == FILTER_ALL)
                    icmp_packet(buffer, size, is_ipv6);
                break;
            case IPPROTO_TCP:
                tcp++;
                if (filter == FILTER_TCP || filter == FILTER_ALL || filter == FILTER_HTTP)
                    tcp_packet(buffer, size, (filter == FILTER_HTTP), filter, is_ipv6);
                break;
            case IPPROTO_UDP:
                udp++;
                if (filter == FILTER_UDP || filter == FILTER_ALL)
                    udp_packet(buffer, size, is_ipv6);
                break;
            default:
                others++;
        }
    }
}

//Displays program usage instructions
void print_usage(char **argv) {
    printf("USAGE: sudo %s <interface> [--filter] [--ipver]\n", argv[0]);
    printf("Filters: --all, --tcp, --udp, --icmp, --http\n");
    printf("IP Versions: --ipv4, --ipv6, --both\n");
    printf("Example: %s eth0 --tcp --ipv6\n", argv[0]);
}

//Sets up capture and processes packets
int main(int argc, char **argv) {
    if (argc < 2) {
        print_usage(argv);
        return 1;
    }

    int filter = FILTER_ALL;
    int ip_mode = IP_MODE_BOTH;
    
    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--tcp") == 0) filter = FILTER_TCP;
        else if (strcmp(argv[i], "--udp") == 0) filter = FILTER_UDP;
        else if (strcmp(argv[i], "--icmp") == 0) filter = FILTER_ICMP;
        else if (strcmp(argv[i], "--http") == 0) filter = FILTER_HTTP;
        else if (strcmp(argv[i], "--ipv4") == 0) ip_mode = IP_MODE_V4;
        else if (strcmp(argv[i], "--ipv6") == 0) ip_mode = IP_MODE_V6;
    }

    logsniff_ipv4 = fopen("sniff_logger_ipv4.txt", "w");
    logsniff_ipv6 = fopen("sniff_logger_ipv6.txt", "w");
    if (!logsniff_ipv4 || !logsniff_ipv6) {
        perror("Failed to open log files");
        return 1;
    }

    signal(SIGINT, INThandler);
    
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("Socket creation failed");
        return 1;
    }

    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, argv[1], IFNAMSIZ);
    if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
        perror("ioctl(SIOCGIFFLAGS) failed");
        close(sock);
        return 1;
    }

    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("ioctl(SIOCSIFFLAGS) failed");
        close(sock);
        return 1;
    }

    printf("Starting capture on interface %s\n", argv[1]);
    printf("Logging IPv4 to sniff_logger_ipv4.txt\n");
    printf("Logging IPv6 to sniff_logger_ipv6.txt\n");

    while (true) {
        unsigned char buffer[65536];
        int packet_size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (packet_size < 0) {
            perror("Recvfrom error");
            break;
        }
        packetCounter(buffer, packet_size, filter, ip_mode);
    }

    ethreq.ifr_flags ^= IFF_PROMISC;
    ioctl(sock, SIOCSIFFLAGS, &ethreq);
    close(sock);
    fclose(logsniff_ipv4);
    fclose(logsniff_ipv6);
    return 0;
}
