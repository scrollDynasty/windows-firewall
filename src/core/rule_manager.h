#ifndef FIREWALL_RULE_MANAGER_H
#define FIREWALL_RULE_MANAGER_H

#include "firewall.h"

int init_rule_manager(FirewallConfig* config);
void cleanup_rule_manager(void);
int add_rule(FirewallRule* rule);
int remove_rule(uint32_t rule_id);
FirewallRule* find_rule(uint32_t rule_id);

#endif // FIREWALL_RULE_MANAGER_H