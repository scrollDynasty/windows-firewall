#ifndef FIREWALL_CONFIG_H
#define FIREWALL_CONFIG_H

#include "../core/firewall.h"

int load_config(const char* filename, FirewallConfig* config);
int save_config(const char* filename, const FirewallConfig* config);

#endif // FIREWALL_CONFIG_H