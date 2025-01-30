#include "firewall.h"
#include "packet_handler.h"
#include "rule_manager.h"
#include "../utils/logger.h"
#include "../utils/config.h"
#include "cJSON.h"
#include <stdio.h>
#include <string.h>
#include <windows.h>
#include <ws2tcpip.h>

static int firewall_enabled = 0;
static FirewallConfig current_config;

int firewall_init(const char* config_file) {
    if (log_init("firewall.log") != 0) {
        printf("Failed to initialize logger\n");
        return -1;
    }

    log_message(LOG_INFO, "Initializing firewall...");

    FILE* f = fopen(config_file, "rb");
    if (!f) {
        log_message(LOG_ERROR, "Failed to open config file: %s", config_file);
        return -1;
    }


    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char* json_str = (char*)malloc(fsize + 1);
    fread(json_str, 1, fsize, f);
    fclose(f);
    json_str[fsize] = 0;

    cJSON* config = cJSON_Parse(json_str);
    free(json_str);

    if (!config) {
        const char* error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            log_message(LOG_ERROR, "Error parsing JSON: %s", error_ptr);
        }
        return -1;
    }

    cJSON* enabled_obj = cJSON_GetObjectItem(config, "enabled");
    if (cJSON_IsBool(enabled_obj)) {
        firewall_enabled = cJSON_IsTrue(enabled_obj);
    }

    cJSON* blocked_domains = cJSON_GetObjectItem(config, "blocked_domains");
    if (blocked_domains) {
        cJSON* domain;
        cJSON_ArrayForEach(domain, blocked_domains) {
            if (cJSON_IsString(domain)) {
                add_blocked_domain(domain->valuestring);
            }
        }
    }

    cJSON* rules = cJSON_GetObjectItem(config, "rules");
    if (rules) {
        current_config.rule_count = 0;
        cJSON* rule;
        cJSON_ArrayForEach(rule, rules) {
            if (current_config.rule_count >= MAX_RULES) break;

            FirewallRule* new_rule = &current_config.rules[current_config.rule_count];

            cJSON* src_ip = cJSON_GetObjectItem(rule, "src_ip");
            cJSON* dst_ip = cJSON_GetObjectItem(rule, "dst_ip");
            cJSON* src_port = cJSON_GetObjectItem(rule, "src_port");
            cJSON* dst_port = cJSON_GetObjectItem(rule, "dst_port");
            cJSON* protocol = cJSON_GetObjectItem(rule, "protocol");
            cJSON* action = cJSON_GetObjectItem(rule, "action");

            if (cJSON_IsString(src_ip)) new_rule->src_ip = inet_addr(src_ip->valuestring);
            if (cJSON_IsString(dst_ip)) new_rule->dst_ip = inet_addr(dst_ip->valuestring);
            if (cJSON_IsNumber(src_port)) new_rule->src_port = src_port->valueint;
            if (cJSON_IsNumber(dst_port)) new_rule->dst_port = dst_port->valueint;
            if (cJSON_IsNumber(protocol)) new_rule->protocol = protocol->valueint;
            if (cJSON_IsNumber(action)) new_rule->action = action->valueint;

            current_config.rule_count++;
        }
    }

    cJSON_Delete(config);

    if (!firewall_enabled) {
        log_message(LOG_WARNING, "Firewall is disabled in configuration");
        return 0;
    }

    log_message(LOG_INFO, "Firewall initialized successfully");
    return 0;
}

int firewall_is_enabled() {
    return firewall_enabled;
}

void firewall_cleanup() {
    log_message(LOG_INFO, "Cleaning up firewall...");
    current_config.rule_count = 0;
    firewall_enabled = 0;
    log_close();
}

const FirewallConfig* get_current_config() {
    return &current_config;
}

int add_firewall_rule(const FirewallRule* rule) {
    if (!rule || current_config.rule_count >= MAX_RULES) return -1;

    current_config.rules[current_config.rule_count] = *rule;
    current_config.rule_count++;
    return 0;
}

int remove_firewall_rule(int rule_index) {
    if (rule_index < 0 || rule_index >= current_config.rule_count) return -1;

    for (int i = rule_index; i < current_config.rule_count - 1; i++) {
        current_config.rules[i] = current_config.rules[i + 1];
    }

    current_config.rule_count--;
    return 0;
}

void update_firewall_rules(const FirewallConfig* new_config) {
    if (!new_config) return;
    memcpy(&current_config, new_config, sizeof(FirewallConfig));
}

void print_firewall_status() {
    printf("\n=== Firewall Status ===\n");
    printf("Status: %s\n", firewall_enabled ? "Enabled" : "Disabled");
    printf("Active Rules: %d\n", current_config.rule_count);
    printf("===================\n\n");

    if (current_config.rule_count > 0) {
        printf("Current Rules:\n");
        for (int i = 0; i < current_config.rule_count; i++) {
            FirewallRule* rule = &current_config.rules[i];
            struct in_addr addr;
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            addr.s_addr = rule->src_ip;
            inet_ntop(AF_INET, &addr, src_ip, INET_ADDRSTRLEN);
            addr.s_addr = rule->dst_ip;
            inet_ntop(AF_INET, &addr, dst_ip, INET_ADDRSTRLEN);

            printf("Rule %d:\n", i + 1);
            printf("  Source IP: %s\n", src_ip);
            printf("  Destination IP: %s\n", dst_ip);
            printf("  Source Port: %d\n", rule->src_port);
            printf("  Destination Port: %d\n", rule->dst_port);
            printf("  Protocol: %d\n", rule->protocol);
            printf("  Action: %s\n",
                   rule->action == ACTION_ALLOW ? "Allow" :
                   rule->action == ACTION_DENY ? "Block" : "Log");
            printf("-------------------\n");
        }
    }
}

int save_rules_to_file(const char* filename) {
    cJSON *root = cJSON_CreateObject();
    cJSON *rules_array = cJSON_CreateArray();

    for (int i = 0; i < current_config.rule_count; i++) {
        cJSON *rule = cJSON_CreateObject();
        struct in_addr addr;
        char ip_str[INET_ADDRSTRLEN];

        addr.s_addr = current_config.rules[i].src_ip;
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        cJSON_AddStringToObject(rule, "src_ip", ip_str);

        addr.s_addr = current_config.rules[i].dst_ip;
        inet_ntop(AF_INET, &addr, ip_str, INET_ADDRSTRLEN);
        cJSON_AddStringToObject(rule, "dst_ip", ip_str);

        cJSON_AddNumberToObject(rule, "src_port", current_config.rules[i].src_port);
        cJSON_AddNumberToObject(rule, "dst_port", current_config.rules[i].dst_port);
        cJSON_AddNumberToObject(rule, "protocol", current_config.rules[i].protocol);
        cJSON_AddNumberToObject(rule, "action", current_config.rules[i].action);

        cJSON_AddItemToArray(rules_array, rule);
    }

    cJSON_AddItemToObject(root, "rules", rules_array);
    cJSON_AddBoolToObject(root, "enabled", firewall_enabled);

    char *json_str = cJSON_Print(root);
    if (!json_str) {
        cJSON_Delete(root);
        return -1;
    }

    FILE *f = fopen(filename, "w");
    if (!f) {
        free(json_str);
        cJSON_Delete(root);
        return -1;
    }

    fputs(json_str, f);
    fclose(f);
    free(json_str);
    cJSON_Delete(root);

    log_message(LOG_INFO, "Rules saved to file: %s", filename);
    return 0;
}

int load_rules_from_file(const char* filename) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        log_message(LOG_ERROR, "Cannot open rules file: %s", filename);
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *json_str = (char*)malloc(fsize + 1);
    if (!json_str) {
        fclose(f);
        return -1;
    }

    fread(json_str, 1, fsize, f);
    fclose(f);
    json_str[fsize] = 0;

    cJSON *root = cJSON_Parse(json_str);
    free(json_str);

    if (!root) {
        log_message(LOG_ERROR, "Failed to parse rules file");
        return -1;
    }

    firewall_init(filename);
    cJSON_Delete(root);

    log_message(LOG_INFO, "Rules loaded from file: %s", filename);
    return 0;
}