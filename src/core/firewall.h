#ifndef FIREWALL_H
#define FIREWALL_H

#include <stdint.h>
#include "packet_handler.h"

#define MAX_RULES 1000
#define MAX_PACKET_SIZE 65535

// Структура для правила файрвола
typedef struct {
    uint32_t id;
    char name[64];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    FirewallAction action;
    char description[256];
} FirewallRule;

// Структура для конфигурации файрвола
typedef struct {
    int enabled;
    char log_file[256];
    int log_level;
    FirewallRule rules[MAX_RULES];
    int rule_count;
} FirewallConfig;

// Основные функции
int firewall_init(const char* config_file);
int firewall_start();
int firewall_stop();
int firewall_reload_config();
void firewall_cleanup();

#endif // FIREWALL_H