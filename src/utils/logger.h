#ifndef FIREWALL_LOGGER_H
#define FIREWALL_LOGGER_H

#include "../core/firewall_types.h"
#include <stdio.h>
#include <stdint.h>

// Прототипы функций
int log_init(const char* filename);
void log_close(void);
void log_message(LogLevel level, const char* format, ...);
void log_set_level(LogLevel level);
LogLevel log_get_level(void);
void log_system_error(const char* message);
void log_packet(LogLevel level, const char* protocol, const char* src_ip,
                uint16_t src_port, const char* dst_ip, uint16_t dst_port,
                const char* action);
void log_cleanup(const char* log_dir, int days_to_keep);
size_t log_get_size(void);

#endif // FIREWALL_LOGGER_H