#ifndef FIREWALL_TCP_H
#define FIREWALL_TCP_H

#include <stdint.h>

#pragma pack(push, 1)
struct tcp_header {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
    uint8_t res1:4;
    uint8_t doff:4;
    uint8_t flags;
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
#pragma pack(pop)

// TCP флаги
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20

#endif // FIREWALL_TCP_H