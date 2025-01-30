#include "packet_handler.h"
#include "rule_manager.h"
#include "../utils/logger.h"
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#define MAX_BLOCKED_DOMAINS 100
#define MAX_DOMAIN_LENGTH 256

static struct {
    char domains[MAX_BLOCKED_DOMAINS][MAX_DOMAIN_LENGTH];
    int count;
} blocked_domains = {0};

static unsigned long packets_total = 0;
static unsigned long packets_blocked = 0;
static unsigned long packets_allowed = 0;
static unsigned long domain_blocks = 0;

#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

void add_blocked_domain(const char* domain) {
    if (blocked_domains.count < MAX_BLOCKED_DOMAINS) {
        strncpy(blocked_domains.domains[blocked_domains.count],
                domain,
                MAX_DOMAIN_LENGTH - 1);
        blocked_domains.domains[blocked_domains.count][MAX_DOMAIN_LENGTH - 1] = '\0';
        blocked_domains.count++;
        log_message(LOG_INFO, "Added blocked domain: %s", domain);
    } else {
        log_message(LOG_WARNING, "Maximum number of blocked domains reached");
    }
}
static uint16_t get_port(const u_char* packet, int offset, int src) {
    struct tcp_header* tcp_header = (struct tcp_header*)(packet + 14 + offset);
    return src ? ntohs(tcp_header->source) : ntohs(tcp_header->dest);
}

static int is_ip_blocked(const char* ip_addr) {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        log_message(LOG_ERROR, "WSAStartup failed");
        return 0;
    }

    for (int i = 0; i < blocked_domains.count; i++) {
        struct addrinfo hints, *result;
        ZeroMemory(&hints, sizeof(hints));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        if (getaddrinfo(blocked_domains.domains[i], NULL, &hints, &result) == 0) {
            for (struct addrinfo* ptr = result; ptr != NULL; ptr = ptr->ai_next) {
                char ipstr[INET_ADDRSTRLEN];
                struct sockaddr_in* addr = (struct sockaddr_in*)ptr->ai_addr;
                inet_ntop(AF_INET, &(addr->sin_addr), ipstr, INET_ADDRSTRLEN);

                if (strcmp(ip_addr, ipstr) == 0) {
                    freeaddrinfo(result);
                    WSACleanup();
                    domain_blocks++;
                    return 1;
                }
            }
            freeaddrinfo(result);
        }
    }

    WSACleanup();
    return 0;
}

FirewallAction evaluate_packet_rules(const struct ip_header* ip_header) {
    const u_char* packet = (const u_char*)ip_header;
    int header_length = (ip_header->ip_hl & 0x0f) * 4;
    uint16_t src_port = 0, dst_port = 0;

    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        src_port = get_port(packet - 14, header_length, 1);
        dst_port = get_port(packet - 14, header_length, 0);

        if (dst_port == 80 || dst_port == 443) {
            struct tcp_header* tcp = (struct tcp_header*)(packet - 14 + header_length);
            struct in_addr dst_addr;
            dst_addr.s_addr = ip_header->ip_dst;
            char* dst_ip = inet_ntoa(dst_addr);

            if (is_ip_blocked(dst_ip)) {
                log_message(LOG_WARNING, "Blocking access to blocked domain IP: %s", dst_ip);
                return ACTION_DENY;
            }
        }

        switch (dst_port) {
            case 80:
                log_message(LOG_INFO, "Blocking HTTP traffic");
                return ACTION_DENY;
            case 443:
                log_message(LOG_INFO, "Logging HTTPS traffic");
                return ACTION_LOG;
            case 23:
                log_message(LOG_INFO, "Blocking Telnet traffic");
                return ACTION_DENY;
            case 20:
            case 21:
                log_message(LOG_INFO, "Logging FTP traffic");
                return ACTION_LOG;
        }
    }

    if (ip_header->ip_p == IPPROTO_ICMP) {
        log_message(LOG_DEBUG, "Allowing ICMP traffic");
        return ACTION_ALLOW;
    }

    return ACTION_ALLOW;
}

void print_packet_info(const struct ip_header* ip_header, FirewallAction action) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    char time_str[26];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->ip_src;
    dst_addr.s_addr = ip_header->ip_dst;

    char port_info[64] = "";
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        const u_char* packet = (const u_char*)ip_header;
        int header_length = (ip_header->ip_hl & 0x0f) * 4;
        uint16_t src_port = get_port(packet - 14, header_length, 1);
        uint16_t dst_port = get_port(packet - 14, header_length, 0);
        snprintf(port_info, sizeof(port_info), ":%d->%d", src_port, dst_port);
    }

    const char* proto_str;
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:  proto_str = "TCP";  break;
        case IPPROTO_UDP:  proto_str = "UDP";  break;
        case IPPROTO_ICMP: proto_str = "ICMP"; break;
        default:           proto_str = "Unknown";
    }

    WORD color;
    const char* action_str;
    switch (action) {
        case ACTION_ALLOW:
            color = FOREGROUND_GREEN;
            action_str = "ALLOWED";
            break;
        case ACTION_DENY:
            color = FOREGROUND_RED;
            action_str = "BLOCKED";
            break;
        case ACTION_LOG:
            color = FOREGROUND_BLUE | FOREGROUND_GREEN;
            action_str = "LOGGED ";
            break;
        default:
            color = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
            action_str = "UNKNOWN";
    }

    SetConsoleTextAttribute(hConsole, color | FOREGROUND_INTENSITY);

    printf("[%s] %s - %s - %s%s -> %s%s\n",
           time_str, action_str, proto_str,
           inet_ntoa(src_addr), port_info,
           inet_ntoa(dst_addr), port_info);

    SetConsoleTextAttribute(hConsole,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    packets_total++;
    if (action == ACTION_DENY) {
        packets_blocked++;
    } else if (action == ACTION_ALLOW) {
        packets_allowed++;
    }

    if (packets_total % 100 == 0) {
        printf("\n=== Packet Statistics ===\n");
        printf("Total packets: %lu\n", packets_total);
        printf("Blocked: %lu\n", packets_blocked);
        printf("Allowed: %lu\n", packets_allowed);
        printf("Domain blocks: %lu\n", domain_blocks);
        printf("=====================\n\n");
    }
}

void process_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ip_header *ip_header = (struct ip_header *)(packet + 14);
    FirewallAction action = evaluate_packet_rules(ip_header);
    print_packet_info(ip_header, action);
}