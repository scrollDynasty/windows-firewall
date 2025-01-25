#include "config.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>

int load_config(const char* filename, FirewallConfig* config) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to open config file: %s", filename);
        return -1;
    }

    // Инициализируем конфиг значениями по умолчанию
    config->enabled = 1;
    config->rule_count = 0;
    strncpy(config->log_file, "firewall.log", sizeof(config->log_file) - 1);
    config->log_level = LOG_INFO;

    // Простое чтение правил (можно расширить позже)
    char line[256];
    while (fgets(line, sizeof(line), fp) && config->rule_count < MAX_RULES) {
        FirewallRule* rule = &config->rules[config->rule_count];

        // Пример формата: src_ip dst_ip src_port dst_port protocol action
        if (sscanf(line, "%u %u %hu %hu %hhu %d",
                   &rule->src_ip,
                   &rule->dst_ip,
                   &rule->src_port,
                   &rule->dst_port,
                   &rule->protocol,
                   &rule->action) == 6) {
            config->rule_count++;
                   }
    }

    fclose(fp);
    return 0;
}

int save_config(const char* filename, const FirewallConfig* config) {
    FILE* fp = fopen(filename, "w");
    if (!fp) {
        log_message(LOG_ERROR, "Failed to open config file for writing: %s", filename);
        return -1;
    }

    for (int i = 0; i < config->rule_count; i++) {
        const FirewallRule* rule = &config->rules[i];
        fprintf(fp, "%u %u %hu %hu %hhu %d\n",
                rule->src_ip,
                rule->dst_ip,
                rule->src_port,
                rule->dst_port,
                rule->protocol,
                rule->action);
    }

    fclose(fp);
    return 0;
}