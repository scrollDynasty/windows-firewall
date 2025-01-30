#ifndef FIREWALL_H
#define FIREWALL_H

#include "firewall_types.h"

// Функции инициализации и управления
int firewall_init(const char* config_file);
void firewall_cleanup(void);
int firewall_is_enabled(void);
int is_firewall_running(void);

// Функции управления конфигурацией
const FirewallConfig* get_current_config(void);
int add_firewall_rule(const FirewallRule* rule);
int remove_firewall_rule(int rule_index);
void update_firewall_rules(const FirewallConfig* new_config);

// Функции для работы с файлами конфигурации
int save_rules_to_file(const char* filename);
int load_rules_from_file(const char* filename);

// Функции статистики и отображения
void print_firewall_status(void);

#endif // FIREWALL_H