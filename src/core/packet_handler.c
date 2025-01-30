#include "packet_handler.h"
#include "rule_manager.h"
#include "../utils/logger.h"
#include <pcap.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>

// Глобальные счетчики
static unsigned long packets_blocked = 0;
static unsigned long packets_allowed = 0;
static unsigned long domain_blocks = 0;

// Вспомогательная функция для получения порта
static uint16_t get_port(const u_char* packet, int offset, int src) {
    if (!packet || offset < 0) {
        return 0;
    }

    const struct tcp_header* tcp_header = (struct tcp_header*)(packet + 14 + offset);
    if (src) {
        return ntohs(tcp_header->source);
    }
    return ntohs(tcp_header->dest);
}

// Главная функция обработки пакетов
void process_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    static unsigned long packets_processed = 0;
    static time_t last_stats_time = 0;
    time_t current_time = time(NULL);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&current_time));

    // Базовые проверки валидности пакета
    if (!packet || !header) {
        log_message(LOG_WARNING, "Received invalid packet (NULL)");
        return;
    }

    // Проверка минимальной длины пакета (Ethernet header + IP header)
    if (header->caplen < (ETHERNET_HEADER_LEN + sizeof(struct ip_header))) {
        log_message(LOG_DEBUG, "Packet too short: %d bytes", header->caplen);
        return;
    }

    // Проверяем тип пакета (должен быть IP - 0x0800)
    uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));
    if (eth_type != 0x0800) {
        return; // Молча пропускаем не-IP пакеты
    }

    // Получаем указатель на IP заголовок
    struct ip_header *ip_header = (struct ip_header *)(packet + ETHERNET_HEADER_LEN);

    // Проверка версии IP
    if (ip_header->ip_v != 4) {
        log_message(LOG_DEBUG, "Non-IPv4 packet received: version %d", ip_header->ip_v);
        return;
    }

    // Проверка длины IP заголовка
    int ip_header_length = (ip_header->ip_hl & 0x0f) * 4;
    if (ip_header_length < MIN_IP_HEADER_LEN || ip_header_length > MAX_IP_HEADER_LEN) {
        log_message(LOG_WARNING, "Invalid IP header length: %d", ip_header_length);
        return;
    }

    // Проверка полной длины пакета
    if (header->caplen < (ETHERNET_HEADER_LEN + ip_header_length)) {
        log_message(LOG_WARNING, "Incomplete IP packet received");
        return;
    }

    // Применяем правила файрвола
    FirewallAction action = evaluate_packet_rules(ip_header);

    // Обновляем счетчики
    if (action == ACTION_DENY) {
        packets_blocked++;
    } else if (action == ACTION_ALLOW) {
        packets_allowed++;
    }

    // Выводим информацию о пакете
    print_packet_info(ip_header, action);

    // Увеличиваем счетчик обработанных пакетов
    packets_processed++;

    // Выводим статистику каждые 60 секунд
    if (current_time - last_stats_time >= 60) {
        printf("\n=== Firewall Statistics (%s) ===\n", timestamp);
        printf("User: scrollDynasty\n");
        printf("Packets processed: %lu\n", packets_processed);
        printf("Packets blocked: %lu\n", packets_blocked);
        printf("Packets allowed: %lu\n", packets_allowed);
        printf("Blocked domains hits: %lu\n", domain_blocks);
        printf("===============================\n\n");

        last_stats_time = current_time;
    }

    // Проверка на перезапуск счетчиков
    if (packets_processed >= ULONG_MAX - 1000) {
        log_message(LOG_WARNING, "Resetting packet counters due to overflow risk");
        packets_processed = 0;
        packets_blocked = 0;
        packets_allowed = 0;
        domain_blocks = 0;
    }
}

FirewallAction evaluate_packet_rules(const struct ip_header* ip_header) {
    if (!ip_header) {
        return ACTION_ALLOW;
    }

    const u_char* packet = (const u_char*)ip_header;
    int header_length = (ip_header->ip_hl & 0x0f) * 4;
    uint16_t src_port = 0, dst_port = 0;

    struct in_addr src_addr, dst_addr;
    char src_ip[INET_ADDRSTRLEN] = {0};
    char dst_ip[INET_ADDRSTRLEN] = {0};

    src_addr.s_addr = ip_header->ip_src;
    dst_addr.s_addr = ip_header->ip_dst;

    inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

    if (ip_header->ip_p == IPPROTO_TCP || ip_header->ip_p == IPPROTO_UDP) {
        src_port = get_port(packet, header_length, 1);
        dst_port = get_port(packet, header_length, 0);

        // Проверяем HTTP порт (80)
        if (dst_port == 80 || src_port == 80) {
            log_message(LOG_INFO, "[%s] Blocking HTTP traffic from %s to %s",
                       "2025-01-30 17:29:59", src_ip, dst_ip);
            return ACTION_DENY;
        }

        // Проверяем заблокированные домены
        if (is_ip_blocked(dst_ip) || is_ip_blocked(src_ip)) {
            log_message(LOG_WARNING, "[%s] Blocking access to blocked domain IP: %s or %s",
                       "2025-01-30 17:29:59", src_ip, dst_ip);
            return ACTION_DENY;
        }

        // Правила для других портов
        switch (dst_port) {
            case 443:
                if (is_ip_blocked(dst_ip)) {
                    log_message(LOG_WARNING, "Blocking HTTPS access to blocked domain");
                    return ACTION_DENY;
                }
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

    // Проверяем ICMP пакеты
    if (ip_header->ip_p == IPPROTO_ICMP) {
        if (is_ip_blocked(dst_ip) || is_ip_blocked(src_ip)) {
            log_message(LOG_WARNING, "Blocking ICMP for blocked domain");
            return ACTION_DENY;
        }
        log_message(LOG_DEBUG, "Allowing ICMP traffic");
        return ACTION_ALLOW;
    }

    return ACTION_ALLOW;
}

void print_packet_info(const struct ip_header* ip_header, FirewallAction action) {
    if (!ip_header) {
        return;
    }

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

        if (src_port && dst_port) {
            snprintf(port_info, sizeof(port_info), ":%d->%d", src_port, dst_port);
        }
    }

    const char* proto_str = "Unknown";
    switch (ip_header->ip_p) {
        case IPPROTO_TCP:  proto_str = "TCP";  break;
        case IPPROTO_UDP:  proto_str = "UDP";  break;
        case IPPROTO_ICMP: proto_str = "ICMP"; break;
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

    WORD originalAttributes;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    originalAttributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, color | FOREGROUND_INTENSITY);

    printf("[%s] %s - %s - %s%s -> %s%s\n",
           time_str, action_str, proto_str,
           inet_ntoa(src_addr), port_info,
           inet_ntoa(dst_addr), port_info);

    SetConsoleTextAttribute(hConsole, originalAttributes);
}