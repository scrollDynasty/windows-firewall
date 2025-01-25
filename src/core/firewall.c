#include "firewall.h"
#include "../utils/logger.h"
#include "../utils/config.h"
#include "rule_manager.h"
#include <stdio.h>
#include <stdlib.h>

static FirewallConfig g_config;
static int g_is_running = 0;

int firewall_init(const char* config_file) {
    log_message(LOG_INFO, "Initializing firewall...");

    if (load_config(config_file, &g_config) != 0) {
        log_message(LOG_ERROR, "Failed to load configuration");
        return -1;
    }

    if (init_rule_manager(&g_config) != 0) {
        log_message(LOG_ERROR, "Failed to initialize rule manager");
        return -1;
    }

    log_message(LOG_INFO, "Firewall initialized successfully");
    return 0;
}

int firewall_start() {
    if (g_is_running) {
        log_message(LOG_WARNING, "Firewall is already running");
        return 0;
    }

    log_message(LOG_INFO, "Starting firewall...");

    if (start_packet_capture() != 0) {
        log_message(LOG_ERROR, "Failed to start packet capture");
        return -1;
    }

    g_is_running = 1;
    return 0;
}

int firewall_stop() {
    if (!g_is_running) {
        return 0;
    }

    log_message(LOG_INFO, "Stopping firewall...");
    stop_packet_capture();
    g_is_running = 0;
    return 0;
}

void firewall_cleanup() {
    firewall_stop();
    cleanup_rule_manager();
    log_message(LOG_INFO, "Firewall cleanup complete");
}