#ifndef FIREWALL_PACKET_HANDLER_H
#define FIREWALL_PACKET_HANDLER_H

#include <../extern/npcap/Include/pcap.h>
#include "../extern/net_headers/ip.h"
#include "../extern/net_headers/tcp.h"
#include "firewall_types.h"
#include <stdbool.h>

// Константы для пакетов
#define ETHERNET_HEADER_LEN 14
#define MIN_IP_HEADER_LEN   20
#define MAX_IP_HEADER_LEN   60

// Константы для портов
#define PORT_HTTP    80
#define PORT_HTTPS   443
#define PORT_FTP_DATA 20
#define PORT_FTP_CTRL 21
#define PORT_TELNET  23
#define PORT_DNS     53

// Структура UDP заголовка
struct udp_header {
    uint16_t source;  // Порт источника
    uint16_t dest;    // Порт назначения
    uint16_t len;     // Длина
    uint16_t check;   // Контрольная сумма
};

// Прототипы функций
void process_packet(const u_char *packet, const struct pcap_pkthdr *header);
FirewallAction evaluate_packet_rules(const struct ip_header* ip_header);
void print_packet_info(const struct ip_header* ip_header, FirewallAction action);

#endif // FIREWALL_PACKET_HANDLER_H