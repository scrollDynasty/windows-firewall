#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <windows.h>
#include "core/firewall.h"
#include "utils/logger.h"
#include "network/packet_capture.h"
#include <pcap.h>

#define VERSION "1.0"
#define BUILD_DATE "2025-01-25"
#define AUTHOR "scrollDynasty"

// Флаг для корректного завершения программы
static volatile int running = 1;

// Обработчик сигналов для корректного завершения
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_BREAK_EVENT) {
        printf("\nReceived shutdown signal. Stopping firewall...\n");
        running = 0;
        return TRUE;
    }
    return FALSE;
}

// Функция для вывода информации о программе
void print_banner() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD originalAttributes;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    originalAttributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("\n");
    printf("================================================\n");
    printf("           Windows Firewall v%s\n", VERSION);
    printf("================================================\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("Author: %s\n", AUTHOR);
    printf("Build Date: %s\n", BUILD_DATE);
    printf("\n");
    SetConsoleTextAttribute(hConsole, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    printf("Features:\n");
    printf("- HTTP traffic blocking (port 80)\n");
    printf("- HTTPS traffic logging (port 443)\n");
    printf("- Telnet blocking (port 23)\n");
    printf("- FTP logging (ports 20, 21)\n");
    printf("- ICMP (ping) monitoring\n");
    printf("================================================\n\n");
    SetConsoleTextAttribute(hConsole, originalAttributes);
}

int main(int argc, char* argv[]) {
    print_banner();

    // Получаем текущую директорию
    char current_path[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, current_path);

    // Создаем директорию logs
    char logs_dir[MAX_PATH];
    snprintf(logs_dir, sizeof(logs_dir), "%s\\logs", current_path);
    CreateDirectory(logs_dir, NULL);

    // Формируем полный путь к лог-файлу
    char log_path[MAX_PATH];
    snprintf(log_path, sizeof(log_path), "%s\\logs\\firewall.log", current_path);

    printf("Log file will be saved to: %s\n\n", log_path);

    // Регистрируем обработчик сигналов
    if (!SetConsoleCtrlHandler(console_handler, TRUE)) {
        printf("ERROR: Could not set control handler\n");
        return 1;
    }

    // Инициализация системы логирования
    if (log_init(log_path) != 0) {
        printf("Failed to initialize logging system at: %s\n", log_path);
        return 1;
    }
    log_set_level(LOG_DEBUG);
    log_message(LOG_INFO, "Firewall initialization started");

    // Получаем список доступных сетевых интерфейсов
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        log_message(LOG_ERROR, "Error finding devices: %s", errbuf);
        return 1;
    }

    // Показываем список доступных интерфейсов
    printf("\nAvailable Network Interfaces:\n");
    printf("------------------------------------------------\n");
    pcap_if_t *d;
    int i = 1;
    for (d = alldevs; d; d = d->next) {
        printf("%d. %s", i++, d->name);
        if (d->description)
            printf(" (%s)", d->description);
        printf("\n");
    }
    printf("------------------------------------------------\n");

    // Просим пользователя выбрать интерфейс
    int inum;
    printf("\nEnter the interface number (1-%d): ", i-1);
    scanf("%d", &inum);

    if (inum < 1 || inum > i-1) {
        log_message(LOG_ERROR, "Interface number out of range");
        printf("Interface number out of range.\n");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Переходим к выбранному интерфейсу
    for (d = alldevs, i = 1; i < inum; d = d->next, i++);

    log_message(LOG_INFO, "Selected interface: %s", d->name);

    // Инициализация файрвола
    if (firewall_init("config/firewall_config.json") != 0) {
        log_message(LOG_ERROR, "Failed to initialize firewall");
        pcap_freealldevs(alldevs);
        return 1;
    }

    // Инициализация захвата пакетов
    if (init_packet_capture(d->name) != 0) {
        log_message(LOG_ERROR, "Failed to initialize packet capture");
        firewall_cleanup();
        pcap_freealldevs(alldevs);
        return 1;
    }

    pcap_freealldevs(alldevs);

    printf("\nFirewall is running. Press Ctrl+C to stop.\n");
    printf("------------------------------------------------\n");
    printf("Active Rules:\n");
    printf("1. Block all HTTP traffic (port 80)\n");
    printf("2. Log all HTTPS traffic (port 443)\n");
    printf("3. Block Telnet traffic (port 23)\n");
    printf("4. Log FTP traffic (ports 20, 21)\n");
    printf("5. Allow ICMP traffic (ping)\n");
    printf("------------------------------------------------\n");
    printf("\nPacket processing started...\n\n");

    // Запуск захвата пакетов
    if (start_packet_capture() != 0) {
        log_message(LOG_ERROR, "Failed to start packet capture");
        firewall_cleanup();
        return 1;
    }

    // Основной цикл
    while (running) {
        Sleep(100); // Небольшая задержка для снижения нагрузки на CPU
    }

    // Очистка и завершение работы
    stop_packet_capture();
    firewall_cleanup();
    log_message(LOG_INFO, "Firewall shutdown complete");
    log_close();

    printf("\nFirewall stopped successfully.\n");
    printf("Log file is available at: %s\n", log_path);

    return 0;
}