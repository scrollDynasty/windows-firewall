#include "config.h"
#include "../core/firewall.h"
#include "logger.h"
#include <stdio.h>
#include <string.h>
#include <cJSON.h>
#include <stdlib.h>
#include <winsock2.h>
static FirewallConfig config;

int load_config(const char* filename) {
    // Инициализация значений по умолчанию
    memset(&config, 0, sizeof(FirewallConfig));
    config.enabled = 1;
    config.rule_count = 0;
    config.domain_count = 0;
    strncpy(config.log_file, "firewall.log", sizeof(config.log_file) - 1);
    config.log_level = LOG_INFO;

    FILE* f = fopen(filename, "rb");
    if (!f) {
        log_message(LOG_WARNING, "Could not open config file: %s, using defaults", filename);
        return 0;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* json_str = (char*)malloc(fsize + 1);
    if (!json_str) {
        fclose(f);
        return -1;
    }

    fread(json_str, 1, fsize, f);
    fclose(f);
    json_str[fsize] = 0;

    cJSON* json = cJSON_Parse(json_str);
    free(json_str);

    if (!json) {
        log_message(LOG_ERROR, "Failed to parse config file");
        return -1;
    }

    // Чтение основных настроек
    cJSON* enabled = cJSON_GetObjectItem(json, "enabled");
    if (cJSON_IsBool(enabled)) {
        config.enabled = cJSON_IsTrue(enabled);
    }

    cJSON* log_level = cJSON_GetObjectItem(json, "log_level");
    if (cJSON_IsString(log_level)) {
        if (strcmp(log_level->valuestring, "DEBUG") == 0) config.log_level = LOG_DEBUG;
        else if (strcmp(log_level->valuestring, "INFO") == 0) config.log_level = LOG_INFO;
        else if (strcmp(log_level->valuestring, "WARNING") == 0) config.log_level = LOG_WARNING;
        else if (strcmp(log_level->valuestring, "ERROR") == 0) config.log_level = LOG_ERROR;
    }

    // Загрузка заблокированных доменов
    cJSON* blocked_domains = cJSON_GetObjectItem(json, "blocked_domains");
    if (blocked_domains && cJSON_IsArray(blocked_domains)) {
        int domain_count = cJSON_GetArraySize(blocked_domains);
        for (int i = 0; i < domain_count && i < MAX_BLOCKED_DOMAINS; i++) {
            cJSON* domain = cJSON_GetArrayItem(blocked_domains, i);
            if (cJSON_IsString(domain)) {
                strncpy(config.blocked_domains[config.domain_count],
                        domain->valuestring,
                        MAX_PATH_LENGTH - 1);
                config.domain_count++;
            }
        }
    }

    // Загрузка правил
    cJSON* rules = cJSON_GetObjectItem(json, "rules");
    if (rules && cJSON_IsArray(rules)) {
        int rule_count = cJSON_GetArraySize(rules);
        for (int i = 0; i < rule_count && i < MAX_RULES; i++) {
            cJSON* rule = cJSON_GetArrayItem(rules, i);
            FirewallRule* new_rule = &config.rules[config.rule_count];

            cJSON* src_ip = cJSON_GetObjectItem(rule, "src_ip");
            cJSON* dst_ip = cJSON_GetObjectItem(rule, "dst_ip");
            cJSON* src_port = cJSON_GetObjectItem(rule, "src_port");
            cJSON* dst_port = cJSON_GetObjectItem(rule, "dst_port");
            cJSON* protocol = cJSON_GetObjectItem(rule, "protocol");
            cJSON* action = cJSON_GetObjectItem(rule, "action");

            if (src_ip && cJSON_IsString(src_ip)) new_rule->src_ip = inet_addr(src_ip->valuestring);
            if (dst_ip && cJSON_IsString(dst_ip)) new_rule->dst_ip = inet_addr(dst_ip->valuestring);
            if (src_port && cJSON_IsNumber(src_port)) new_rule->src_port = src_port->valueint;
            if (dst_port && cJSON_IsNumber(dst_port)) new_rule->dst_port = dst_port->valueint;
            if (protocol && cJSON_IsNumber(protocol)) new_rule->protocol = protocol->valueint;
            if (action && cJSON_IsNumber(action)) new_rule->action = action->valueint;

            config.rule_count++;
        }
    }

    cJSON_Delete(json);
    return 0;
}

const FirewallConfig* get_config(void) {
    return &config;
}

void set_config(const FirewallConfig* new_config) {
    if (new_config) {
        memcpy(&config, new_config, sizeof(FirewallConfig));
    }
}