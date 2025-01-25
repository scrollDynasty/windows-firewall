#include "logger.h"
#include <stdio.h>
#include <time.h>
#include <stdarg.h>
#include <string.h>
#include <windows.h>

static FILE* log_file = NULL;
static int current_log_level = LOG_INFO;
static char log_file_path[MAX_PATH] = {0};

// Преобразование уровня лога в строку
static const char* log_level_to_string(LogLevel level) {
    switch (level) {
        case LOG_DEBUG:   return "DEBUG";
        case LOG_INFO:    return "INFO";
        case LOG_WARNING: return "WARNING";
        case LOG_ERROR:   return "ERROR";
        default:          return "UNKNOWN";
    }
}

// Получение цвета для уровня лога
static WORD get_level_color(LogLevel level) {
    switch (level) {
        case LOG_DEBUG:   return FOREGROUND_BLUE | FOREGROUND_GREEN;
        case LOG_INFO:    return FOREGROUND_GREEN;
        case LOG_WARNING: return FOREGROUND_RED | FOREGROUND_GREEN;
        case LOG_ERROR:   return FOREGROUND_RED;
        default:          return FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE;
    }
}

void check_directory_permissions(const char* path) {
    DWORD attributes = GetFileAttributes(path);
    if (attributes == INVALID_FILE_ATTRIBUTES) {
        DWORD error = GetLastError();
        printf("Error checking directory %s: %lu\n", path, error);
        printf("Make sure you're running with administrator privileges.\n");
    } else {
        printf("Directory %s is %s\n", path,
               (attributes & FILE_ATTRIBUTE_READONLY) ? "read-only" : "writable");
    }
}

const char* get_log_path(void) {
    return log_file_path;
}

int log_init(const char* filename) {
    if (log_file != NULL) {
        fclose(log_file);
    }

    // Сохраняем полный путь к файлу
    strncpy(log_file_path, filename, MAX_PATH - 1);
    log_file_path[MAX_PATH - 1] = '\0';

    // Проверяем директорию перед созданием файла
    char dir_path[MAX_PATH];
    strncpy(dir_path, filename, MAX_PATH - 1);
    char* last_slash = strrchr(dir_path, '\\');
    if (last_slash) {
        *last_slash = '\0';
        check_directory_permissions(dir_path);
    }

    log_file = fopen(filename, "a");
    if (log_file == NULL) {
        printf("Error: Could not open log file: %s\n", filename);
        printf("Make sure you have write permissions and run as administrator.\n");
        return -1;
    }

    // Записываем начальное сообщение
    time_t now = time(NULL);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "\n=================================================\n");
    fprintf(log_file, "[%s] === Firewall Session Started ===\n", timestamp);
    fprintf(log_file, "Log file location: %s\n", filename);
    fprintf(log_file, "User: scrollDynasty\n");
    fprintf(log_file, "=================================================\n\n");
    fflush(log_file);

    printf("Successfully opened log file at: %s\n", filename);
    return 0;
}

void log_set_level(LogLevel level) {
    current_log_level = level;
}

void log_message(LogLevel level, const char* format, ...) {
    if (level < current_log_level || log_file == NULL) {
        return;
    }

    // Получаем текущее время
    time_t now = time(NULL);
    char timestamp[26];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

    // Записываем в файл
    fprintf(log_file, "[%s][%s] ", timestamp, log_level_to_string(level));
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
    fprintf(log_file, "\n");
    fflush(log_file);

    // Выводим в консоль с цветом
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    WORD originalAttributes;
    CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
    GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
    originalAttributes = consoleInfo.wAttributes;

    SetConsoleTextAttribute(hConsole, get_level_color(level));
    printf("[%s][%s] ", timestamp, log_level_to_string(level));
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("\n");

    SetConsoleTextAttribute(hConsole, originalAttributes);
}

void log_close(void) {
    if (log_file != NULL) {
        time_t now = time(NULL);
        char timestamp[26];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        fprintf(log_file, "\n=================================================\n");
        fprintf(log_file, "[%s] === Firewall Session Ended ===\n", timestamp);
        fprintf(log_file, "=================================================\n");
        fclose(log_file);
        log_file = NULL;
    }
}