#include "packet_handler.h"
#include "rule_manager.h"
#include "../utils/logger.h"
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <windows.h>
#include <ws2tcpip.h>

// Счетчики пакетов
static unsigned long packets_total = 0;
static unsigned long packets_blocked = 0;
static unsigned long packets_allowed = 0;

// Получение TCP/UDP порта из пакета
static uint16_t get_port(const u_char* packet, int offset, int src) {
    struct tcp_header* tcp_header = (struct tcp_header*)(packet + 14 + offset);
    return src ? ntohs(tcp_header->source) : ntohs(tcp_header->dest);
}

FirewallAction evaluate_packet_rules(const struct ip_header* ip_header) {
    // Получаем TCP заголовок
    const u_char* packet = (const u_char*)ip_header;
    int header_length = (ip_header->ip_hl & 0x0f) * 4;
    uint16_t src_port = 0, dst_port = 0;

    // Получаем порты только для TCP и UDP
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        src_port = get_port(packet - 14, header_length, 1);
        dst_port = get_port(packet - 14, header_length, 0);

        // Выводим дополнительную отладочную информацию
        log_message(LOG_DEBUG, "Packet: proto=%d, src_port=%d, dst_port=%d",
                   ip_header->ip_p, src_port, dst_port);
    }

    // Правило 1: Блокировать весь HTTP трафик (порт 80)
    if (dst_port == 80) {
        log_message(LOG_INFO, "Blocking HTTP traffic to port 80");
        return ACTION_DENY;
    }

    // Правило 2: Логировать весь HTTPS трафик (порт 443)
    if (dst_port == 443) {
        log_message(LOG_INFO, "Logging HTTPS traffic to port 443");
        return ACTION_LOG;
    }

    // Правило 3: Блокировать telnet (порт 23)
    if (dst_port == 23) {
        log_message(LOG_INFO, "Blocking Telnet traffic to port 23");
        return ACTION_DENY;
    }

    // Правило 4: Логировать FTP трафик (порты 20, 21)
    if (dst_port == 20 || dst_port == 21) {
        log_message(LOG_INFO, "Logging FTP traffic");
        return ACTION_LOG;
    }

    // Правило 5: Разрешить ICMP (ping)
    if (ip_header->ip_p == IPPROTO_ICMP) {
        log_message(LOG_DEBUG, "Allowing ICMP traffic");
        return ACTION_ALLOW;
    }

    // По умолчанию разрешаем пакет
    return ACTION_ALLOW;
}

void print_packet_info(const struct ip_header* ip_header, FirewallAction action) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    char time_str[26];
    time_t now = time(NULL);
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Преобразуем IP-адреса в строковый формат
    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_header->ip_src;
    dst_addr.s_addr = ip_header->ip_dst;

    // Получаем информацию о портах для TCP/UDP
    char port_info[64] = "";
    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        const u_char* packet = (const u_char*)ip_header;
        int header_length = (ip_header->ip_hl & 0x0f) * 4;
        uint16_t src_port = get_port(packet - 14, header_length, 1);
        uint16_t dst_port = get_port(packet - 14, header_length, 0);
        snprintf(port_info, sizeof(port_info), ":%d->%d", src_port, dst_port);
    }

    // Определяем протокол
    const char* proto_str;
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            proto_str = "TCP";
            break;
        case IPPROTO_UDP:
            proto_str = "UDP";
            break;
        case IPPROTO_ICMP:
            proto_str = "ICMP";
            break;
        default:
            proto_str = "Unknown";
    }

    // Выбираем цвет в зависимости от действия
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

    // Устанавливаем цвет
    SetConsoleTextAttribute(hConsole, color | FOREGROUND_INTENSITY);

    // Выводим информацию о пакете
    printf("[%s] %s - %s - %s%s -> %s%s\n",
           time_str, action_str, proto_str,
           inet_ntoa(src_addr), port_info,
           inet_ntoa(dst_addr), port_info);

    // Возвращаем стандартный цвет
    SetConsoleTextAttribute(hConsole,
        FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE);

    // Обновляем статистику
    packets_total++;
    if (action == ACTION_DENY) {
        packets_blocked++;
    } else if (action == ACTION_ALLOW) {
        packets_allowed++;
    }

    // Выводим статистику каждые 100 пакетов
    if (packets_total % 100 == 0) {
        printf("\n=== Packet Statistics ===\n");
        printf("Total packets: %lu\n", packets_total);
        printf("Blocked: %lu\n", packets_blocked);
        printf("Allowed: %lu\n", packets_allowed);
        printf("=====================\n\n");
    }
}

void process_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ip_header *ip_header = (struct ip_header *)(packet + 14); // Skip Ethernet header

    // Проверяем правила для данного пакета
    FirewallAction action = evaluate_packet_rules(ip_header);

    // Выводим информацию о пакете
    print_packet_info(ip_header, action);
}