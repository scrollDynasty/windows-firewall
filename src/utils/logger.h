#ifndef FIREWALL_LOGGER_H
#define FIREWALL_LOGGER_H

typedef enum {
    LOG_DEBUG = 0,
    LOG_INFO = 1,
    LOG_WARNING = 2,
    LOG_ERROR = 3
} LogLevel;

// Инициализация системы логирования
int log_init(const char* filename);

// Установка уровня логирования
void log_set_level(LogLevel level);

// Запись сообщения в лог
void log_message(LogLevel level, const char* format, ...);

// Закрытие системы логирования
void log_close(void);

#endif // FIREWALL_LOGGER_H