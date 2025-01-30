#include "rule_manager.h"
#include "../utils/logger.h"
#include <string.h>
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

// Глобальная переменная для хранения заблокированных доменов
static BlockedDomains blocked_domains = {{{0}}, 0};

// Инициализация менеджера правил
void init_rule_manager(void) {
    blocked_domains.count = 0;
    log_message(LOG_INFO, "Rule manager initialized");
}

// Очистка менеджера правил
void cleanup_rule_manager(void) {
    blocked_domains.count = 0;
    log_message(LOG_INFO, "Rule manager cleaned up");
}

// Добавление домена в список заблокированных
void add_blocked_domain(const char* domain) {
    if (!domain) {
        log_message(LOG_ERROR, "Attempted to add NULL domain");
        return;
    }

    if (blocked_domains.count >= MAX_BLOCKED_DOMAINS) {
        log_message(LOG_WARNING, "Maximum number of blocked domains reached");
        return;
    }

    // Проверяем, не существует ли уже такой домен
    for (int i = 0; i < blocked_domains.count; i++) {
        if (strcmp(blocked_domains.domains[i], domain) == 0) {
            log_message(LOG_INFO, "Domain %s is already blocked", domain);
            return;
        }
    }

    // Добавляем новый домен
    strncpy(blocked_domains.domains[blocked_domains.count],
            domain,
            MAX_DOMAIN_LENGTH - 1);
    blocked_domains.domains[blocked_domains.count][MAX_DOMAIN_LENGTH - 1] = '\0';
    blocked_domains.count++;

    log_message(LOG_INFO, "Added blocked domain: %s", domain);
}

// Проверка, заблокирован ли IP-адрес
bool is_ip_blocked(const char* ip) {
    if (!ip) {
        log_message(LOG_ERROR, "Attempted to check NULL IP");
        return false;
    }

    // Проверяем каждый заблокированный домен
    for (int i = 0; i < blocked_domains.count; i++) {
        struct addrinfo hints = {0}, *result;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;

        // Пытаемся получить IP-адрес для домена
        if (getaddrinfo(blocked_domains.domains[i], NULL, &hints, &result) == 0) {
            struct addrinfo *rp;
            for (rp = result; rp != NULL; rp = rp->ai_next) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
                char addr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ipv4->sin_addr), addr, INET_ADDRSTRLEN);

                if (strcmp(addr, ip) == 0) {
                    freeaddrinfo(result);
                    log_message(LOG_INFO, "IP %s matches blocked domain %s",
                              ip, blocked_domains.domains[i]);
                    return true;
                }
            }
            freeaddrinfo(result);
        }
    }

    return false;
}

// Получение списка заблокированных доменов
const BlockedDomains* get_blocked_domains(void) {
    return &blocked_domains;
}