#ifndef FIREWALL_RULE_MANAGER_H
#define FIREWALL_RULE_MANAGER_H

#include <stdbool.h>
#include "firewall.h"

#define MAX_BLOCKED_DOMAINS 100
#define MAX_DOMAIN_LENGTH 256

// Структура для хранения заблокированных доменов
typedef struct {
    char domains[MAX_BLOCKED_DOMAINS][MAX_DOMAIN_LENGTH];
    int count;
} BlockedDomains;

// Функции для управления заблокированными доменами
void add_blocked_domain(const char* domain);
bool is_ip_blocked(const char* ip);

// Другие функции rule_manager, если они есть
void init_rule_manager(void);
void cleanup_rule_manager(void);

#endif // FIREWALL_RULE_MANAGER_H