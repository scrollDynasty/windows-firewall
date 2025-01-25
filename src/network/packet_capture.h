#ifndef FIREWALL_PACKET_CAPTURE_H
#define FIREWALL_PACKET_CAPTURE_H

#include <pcap.h>
#include "../extern/net_headers/ip.h"
#include "../extern/net_headers/tcp.h"

int init_packet_capture(const char* interface_name);
int start_packet_capture(void);
int stop_packet_capture(void);
void process_packet(const u_char* packet, const struct pcap_pkthdr* header);

#endif // FIREWALL_PACKET_CAPTURE_H