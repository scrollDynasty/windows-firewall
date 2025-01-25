#ifndef FIREWALL_IP_H
#define FIREWALL_IP_H

#include <stdint.h>

// Удалим дублирующиеся определения, которые уже есть в Windows
#ifndef WIN32
    #define IPPROTO_IP      0   /* Dummy protocol for TCP */
    #define IPPROTO_ICMP    1   /* Internet Control Message Protocol */
    #define IPPROTO_IGMP    2   /* Internet Group Management Protocol */
    #define IPPROTO_TCP     6   /* Transmission Control Protocol */
    #define IPPROTO_UDP    17   /* User Datagram Protocol */
    #define IPPROTO_IPV6   41   /* IPv6 header */
    #define IPPROTO_SCTP  132   /* Stream Control Transmission Protocol */
    #define IPPROTO_RAW   255   /* Raw IP packets */
#endif

// Определяем собственные флаги, которые не конфликтуют с Windows
#define FW_IP_RF 0x8000        /* Reserved fragment flag */
#define FW_IP_DF 0x4000        /* Don't fragment flag */
#define FW_IP_MF 0x2000        /* More fragments flag */
#define FW_IP_OFFMASK 0x1fff   /* Mask for fragmenting bits */

// Максимальные значения
#define FW_IP_MAXPACKET 65535  /* Maximum packet size */
#define FW_MAXTTL       255    /* Maximum time to live */
#define FW_IPDEFTTL     64     /* Default TTL */

// Определение версии IP
#define FW_IPVERSION    4      /* IP version number */

// Определение типа сервиса (TOS)
#define FW_IPTOS_LOWDELAY          0x10
#define FW_IPTOS_THROUGHPUT        0x08
#define FW_IPTOS_RELIABILITY       0x04
#define FW_IPTOS_LOWCOST          0x02
#define FW_IPTOS_MINCOST          FW_IPTOS_LOWCOST

#pragma pack(push, 1)
struct ip_header {
    uint8_t  ip_hl:4;        /* Header length in 32-bit words */
    uint8_t  ip_v:4;         /* Version */
    uint8_t  ip_tos;         /* Type of service */
    uint16_t ip_len;         /* Total length in bytes */
    uint16_t ip_id;          /* Identification */
    uint16_t ip_off;         /* Fragment offset field */
    uint8_t  ip_ttl;         /* Time to live */
    uint8_t  ip_p;           /* Protocol */
    uint16_t ip_sum;         /* Checksum */
    uint32_t ip_src;         /* Source address */
    uint32_t ip_dst;         /* Destination address */
};
#pragma pack(pop)

// Вспомогательные макросы с префиксом FW_ чтобы избежать конфликтов
#define FW_IP_HEADER_LENGTH(ip)  ((((ip)->ip_hl) & 0x0f) * 4)
#define FW_IP_VERSION(ip)        (((ip)->ip_v) & 0x0f)
#define FW_IP_OFFSET(ip)         ntohs((ip)->ip_off)
#define FW_IP_DF(ip)            (ntohs((ip)->ip_off) & FW_IP_DF)
#define FW_IP_MF(ip)            (ntohs((ip)->ip_off) & FW_IP_MF)
#define FW_IP_FRAGMENT(ip)      (ntohs((ip)->ip_off) & FW_IP_OFFMASK)
#define FW_IP_PROTOCOL(ip)      ((ip)->ip_p)
#define FW_IP_TTL(ip)           ((ip)->ip_ttl)
#define FW_IP_TOS(ip)           ((ip)->ip_tos)

// Вспомогательные функции для работы с адресами (inline)
static inline uint32_t ip_addr_to_uint32(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static inline void uint32_to_ip_addr(uint32_t addr, uint8_t *a, uint8_t *b, uint8_t *c, uint8_t *d) {
    *a = (addr >> 24) & 0xFF;
    *b = (addr >> 16) & 0xFF;
    *c = (addr >> 8) & 0xFF;
    *d = addr & 0xFF;
}

// Функции для проверки адресов (inline)
static inline int is_private_ip(uint32_t addr) {
    uint8_t first_octet = (addr >> 24) & 0xFF;
    uint8_t second_octet = (addr >> 16) & 0xFF;
    uint8_t third_octet = (addr >> 8) & 0xFF;

    // 10.0.0.0/8
    if (first_octet == 10)
        return 1;

    // 172.16.0.0/12
    if (first_octet == 172 && (second_octet >= 16 && second_octet <= 31))
        return 1;

    // 192.168.0.0/16 (включая вашу сеть 192.168.100.0)
    if (first_octet == 192 && second_octet == 168)
        return 1;

    return 0;
}

static inline int is_loopback_ip(uint32_t addr) {
    return ((addr >> 24) & 0xFF) == 127;
}

static inline int is_multicast_ip(uint32_t addr) {
    return ((addr >> 24) & 0xF0) == 0xE0;
}

static inline int is_broadcast_ip(uint32_t addr) {
    return addr == 0xFFFFFFFF;
}

#endif // FIREWALL_IP_H