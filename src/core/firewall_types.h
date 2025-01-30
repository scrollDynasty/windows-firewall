#ifndef FIREWALL_TYPES_H
#define FIREWALL_TYPES_H

#include <stdint.h>
#include <time.h>

#define MAX_RULES 100
#define MAX_PATH_LENGTH 256
#define MAX_BLOCKED_DOMAINS 100
#define MAX_LOG_LENGTH 1024

// Определяем возможные действия для пакетов
typedef enum {
    ACTION_DENY,   // 0 - Заблокировать пакет
    ACTION_LOG,    // 1 - Логировать пакет
    ACTION_ALLOW   // 2 - Разрешить пакет
} FirewallAction;

// Уровни логирования
typedef enum {
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARNING,
    LOG_ERROR
} LogLevel;

// Структура правила файрвола
typedef struct {
    uint32_t src_ip;      // IP-адрес источника
    uint32_t dst_ip;      // IP-адрес назначения
    uint16_t src_port;    // Порт источника
    uint16_t dst_port;    // Порт назначения
    uint8_t protocol;     // Протокол (TCP, UDP, ICMP)
    FirewallAction action; // Действие
} FirewallRule;

// Структура конфигурации файрвола
typedef struct {
    FirewallRule rules[MAX_RULES];  // Массив правил
    int rule_count;                 // Количество правил
    int enabled;                    // Флаг включения файрвола
    char log_file[MAX_PATH_LENGTH]; // Путь к файлу логов
    LogLevel log_level;            // Уровень логирования
    char blocked_domains[MAX_BLOCKED_DOMAINS][MAX_PATH_LENGTH]; // Заблокированные домены
    int domain_count;              // Количество заблокированных доменов
    time_t last_update;           // Время последнего обновления
    char current_user[64];        // Текущий пользователь
} FirewallConfig;

// Константы для портов
#define PORT_HTTP        80   // HTTP
#define PORT_HTTPS       443  // HTTPS
#define PORT_FTP_DATA    20   // FTP Data
#define PORT_FTP_CTRL    21   // FTP Control
#define PORT_TELNET      23   // Telnet
#define PORT_DNS         53   // DNS
#define PORT_SMTP        25   // SMTP
#define PORT_POP3        110  // POP3
#define PORT_IMAP        143  // IMAP
#define PORT_SSH         22   // SSH

#endif // FIREWALL_TYPES_H