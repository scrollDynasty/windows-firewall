#include "logger.h"
#include <stdarg.h>
#include <time.h>
#include <windows.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LOG_LINE 2048

static FILE* log_file = NULL;
static LogLevel current_level = LOG_INFO;
static HANDLE console_handle;
static const char* current_user = "scrollDynasty";
static const char* current_date = "2025-01-30 17:54:16";

// Цветовые схемы для разных уровней логирования
static const struct {
    const char* name;
    WORD color;
} log_levels[] = {
    { "DEBUG",   FOREGROUND_BLUE | FOREGROUND_INTENSITY },
    { "INFO",    FOREGROUND_GREEN | FOREGROUND_INTENSITY },
    { "WARNING", FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY },
    { "ERROR",   FOREGROUND_RED | FOREGROUND_INTENSITY }
};

int log_init(const char* filename) {
    if (log_file) {
        fclose(log_file);
    }

    log_file = fopen(filename, "a");
    if (!log_file) {
        printf("Failed to open log file: %s\n", filename);
        return -1;
    }

    console_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    if (console_handle == INVALID_HANDLE_VALUE) {
        printf("Failed to get console handle\n");
        fclose(log_file);
        log_file = NULL;
        return -1;
    }

    // Записываем начальное сообщение в лог
    fprintf(log_file, "\n[%s] Logging started by user: %s\n", current_date, current_user);
    fprintf(log_file, "----------------------------------------\n");
    fflush(log_file);

    return 0;
}

void log_close(void) {
    if (log_file) {
        fprintf(log_file, "\n[%s] Logging stopped by user: %s\n", current_date, current_user);
        fprintf(log_file, "----------------------------------------\n");
        fflush(log_file);
        fclose(log_file);
        log_file = NULL;
    }
}

void log_set_level(LogLevel level) {
    if (level >= LOG_DEBUG && level <= LOG_ERROR) {
        current_level = level;
        log_message(LOG_INFO, "Log level changed to %s", log_levels[level].name);
    }
}

LogLevel log_get_level(void) {
    return current_level;
}

void log_message(LogLevel level, const char* format, ...) {
    if (level < current_level || !format) return;

    // Получаем текущее время
    time_t now;
    time(&now);
    struct tm* timeinfo = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", timeinfo);

    // Подготавливаем буфер для сообщения
    char message[MAX_LOG_LINE];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    // Сохраняем текущие атрибуты консоли
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(console_handle, &csbi);
    WORD original_attributes = csbi.wAttributes;

    // Устанавливаем цвет для уровня логирования
    SetConsoleTextAttribute(console_handle, log_levels[level].color);

    // Выводим в консоль
    printf("[%s][%s] %s\n", timestamp, log_levels[level].name, message);

    // Возвращаем оригинальные атрибуты
    SetConsoleTextAttribute(console_handle, original_attributes);

    // Записываем в файл
    if (log_file) {
        fprintf(log_file, "[%s][%s] %s\n", timestamp, log_levels[level].name, message);
        fflush(log_file);
    }
}

// Функция для логирования системных ошибок
void log_system_error(const char* message) {
    DWORD error_code = GetLastError();
    char* error_message = NULL;

    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&error_message,
        0,
        NULL
    );

    if (error_message) {
        // Удаляем символы новой строки из системного сообщения
        char* newline = strchr(error_message, '\r');
        if (newline) *newline = '\0';

        log_message(LOG_ERROR, "%s: %s (Error code: %lu)",
                   message, error_message, error_code);
        LocalFree(error_message);
    } else {
        log_message(LOG_ERROR, "%s: Unknown error (Error code: %lu)",
                   message, error_code);
    }
}

// Функция для логирования пакетов
void log_packet(LogLevel level, const char* protocol, const char* src_ip,
                uint16_t src_port, const char* dst_ip, uint16_t dst_port,
                const char* action) {
    char message[MAX_LOG_LINE];
    snprintf(message, sizeof(message),
             "%s - %s - %s:%d->%d -> %s:%d->%d",
             action, protocol, src_ip, src_port, dst_port,
             dst_ip, src_port, dst_port);
    log_message(level, "%s", message);
}

// Функция для очистки старых логов
void log_cleanup(const char* log_dir, int days_to_keep) {
    WIN32_FIND_DATA find_data;
    char search_path[MAX_PATH];
    HANDLE find_handle;
    time_t now;
    time(&now);

    snprintf(search_path, sizeof(search_path), "%s\\*.log", log_dir);
    find_handle = FindFirstFile(search_path, &find_data);

    if (find_handle == INVALID_HANDLE_VALUE) {
        log_system_error("Failed to search log directory");
        return;
    }

    do {
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", log_dir, find_data.cFileName);

        FILETIME ft = find_data.ftLastWriteTime;
        ULARGE_INTEGER ull;
        ull.LowPart = ft.dwLowDateTime;
        ull.HighPart = ft.dwHighDateTime;

        // Преобразуем время файла в time_t
        time_t file_time = (time_t)((ull.QuadPart - 116444736000000000ULL) / 10000000ULL);
        double diff_days = difftime(now, file_time) / (24 * 3600);

        if (diff_days > days_to_keep) {
            if (DeleteFile(full_path)) {
                log_message(LOG_INFO, "Deleted old log file: %s", find_data.cFileName);
            } else {
                log_system_error("Failed to delete old log file");
            }
        }
    } while (FindNextFile(find_handle, &find_data));

    FindClose(find_handle);
}

// Функция для получения текущего размера лог-файла
size_t log_get_size(void) {
    if (!log_file) return 0;

    long current_pos = ftell(log_file);
    fseek(log_file, 0, SEEK_END);
    long size = ftell(log_file);
    fseek(log_file, current_pos, SEEK_SET);

    return (size_t)size;
}