#ifndef FIREWALL_PACKET_HANDLER_H
#define FIREWALL_PACKET_HANDLER_H

#include <../extern/npcap/Include/pcap.h>
#include "../extern/net_headers/ip.h"
#include "../extern/net_headers/tcp.h"

// Определяем возможные действия для пакетов
typedef enum {
    ACTION_ALLOW,
    ACTION_DENY,
    ACTION_LOG
} FirewallAction;

// Прототипы функций
void process_packet(const u_char *packet, const struct pcap_pkthdr *header);
FirewallAction evaluate_packet_rules(const struct ip_header* ip_header);
void print_packet_info(const struct ip_header* ip_header, FirewallAction action);

#endif // FIREWALL_PACKET_HANDLER_H