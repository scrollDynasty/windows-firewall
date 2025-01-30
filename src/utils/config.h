#ifndef FIREWALL_CONFIG_H
#define FIREWALL_CONFIG_H

#include "../core/firewall_types.h"

int load_config(const char* filename);
const FirewallConfig* get_config(void);
void set_config(const FirewallConfig* new_config);

#endif // FIREWALL_CONFIG_H