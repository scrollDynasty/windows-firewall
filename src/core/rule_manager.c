#include "rule_manager.h"
#include "../utils/logger.h"
#include <stdlib.h>
#include <string.h>

static FirewallConfig* g_config = NULL;

int init_rule_manager(FirewallConfig* config) {
    if (!config) {
        log_message(LOG_ERROR, "Rule manager initialization failed: null config");
        return -1;
    }

    g_config = config;
    log_message(LOG_INFO, "Rule manager initialized with %d rules", config->rule_count);
    return 0;
}

void cleanup_rule_manager(void) {
    g_config = NULL;
    log_message(LOG_INFO, "Rule manager cleaned up");
}

int add_rule(FirewallRule* rule) {
    if (!g_config || !rule) {
        return -1;
    }

    if (g_config->rule_count >= MAX_RULES) {
        log_message(LOG_ERROR, "Cannot add rule: maximum number of rules reached");
        return -1;
    }

    memcpy(&g_config->rules[g_config->rule_count], rule, sizeof(FirewallRule));
    g_config->rule_count++;

    log_message(LOG_INFO, "Added new rule: ID %d", rule->id);
    return 0;
}

int remove_rule(uint32_t rule_id) {
    if (!g_config) {
        return -1;
    }

    for (int i = 0; i < g_config->rule_count; i++) {
        if (g_config->rules[i].id == rule_id) {
            // Сдвигаем все последующие правила
            for (int j = i; j < g_config->rule_count - 1; j++) {
                memcpy(&g_config->rules[j], &g_config->rules[j + 1], sizeof(FirewallRule));
            }
            g_config->rule_count--;
            log_message(LOG_INFO, "Removed rule: ID %d", rule_id);
            return 0;
        }
    }

    log_message(LOG_WARNING, "Rule not found: ID %d", rule_id);
    return -1;
}

FirewallRule* find_rule(uint32_t rule_id) {
    if (!g_config) {
        return NULL;
    }

    for (int i = 0; i < g_config->rule_count; i++) {
        if (g_config->rules[i].id == rule_id) {
            return &g_config->rules[i];
        }
    }

    return NULL;
}