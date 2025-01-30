#ifndef FIREWALL_LOGGER_H
#define FIREWALL_LOGGER_H

#include "../core/firewall_types.h"
#include <stdio.h>

// Прототипы функций
int log_init(const char* filename);
void log_close(void);
void log_message(LogLevel level, const char* format, ...);
void log_set_level(LogLevel level);
LogLevel log_get_level(void);

#endif // FIREWALL_LOGGER_H