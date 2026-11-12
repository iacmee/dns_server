#define _POSIX_C_SOURCE 200809L
#include "logger.h"

#include <pthread.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define LOGGER_TIMESTAMP_SIZE 32

typedef struct s_logger_state
{
    t_log_level level;
    FILE *output;
    bool color;
    bool color_was_set;
    pthread_mutex_t mutex;
} t_logger_state;

static t_logger_state g_logger = {
    .level = LOG_LEVEL_DEBUG,
    .output = NULL,
    .color = false,
    .color_was_set = false,
    .mutex = PTHREAD_MUTEX_INITIALIZER
};

static const char *level_name(t_log_level level)
{
    static const char *const names[] = {
        "DEBUG", "INFO", "WARNING", "ERROR"
    };

    if (level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_ERROR)
        return "UNKNOWN";
    return names[level];
}

static const char *level_color(t_log_level level)
{
    static const char *const colors[] = {
        "\033[36m", "\033[32m", "\033[33m", "\033[31m"
    };

    if (level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_ERROR)
        return "";
    return colors[level];
}

static const char *base_name(const char *path)
{
    const char *separator;

    if (path == NULL)
        return "?";
    separator = strrchr(path, '/');
    if (separator == NULL)
        return path;
    return separator + 1;
}

static void format_timestamp(char output[LOGGER_TIMESTAMP_SIZE])
{
    struct timespec now;
    struct tm local_time;
    size_t length;

    if (clock_gettime(CLOCK_REALTIME, &now) != 0
        || localtime_r(&now.tv_sec, &local_time) == NULL)
    {
        strcpy(output, "0000-00-00 00:00:00.000");
        return;
    }
    length = strftime(output, LOGGER_TIMESTAMP_SIZE,
                      "%Y-%m-%d %H:%M:%S", &local_time);
    if (length == 0)
    {
        strcpy(output, "0000-00-00 00:00:00.000");
        return;
    }
    (void)snprintf(output + length, LOGGER_TIMESTAMP_SIZE - length,
                   ".%03ld", now.tv_nsec / 1000000L);
}

void logger_set_level(t_log_level level)
{
    if (level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_NONE)
        return;
    pthread_mutex_lock(&g_logger.mutex);
    g_logger.level = level;
    pthread_mutex_unlock(&g_logger.mutex);
}

void logger_set_output(FILE *output)
{
    pthread_mutex_lock(&g_logger.mutex);
    g_logger.output = output != NULL ? output : stderr;
    pthread_mutex_unlock(&g_logger.mutex);
}

void logger_set_color(bool enabled)
{
    pthread_mutex_lock(&g_logger.mutex);
    g_logger.color = enabled;
    g_logger.color_was_set = true;
    pthread_mutex_unlock(&g_logger.mutex);
}

static void logger_vlog(t_log_level level, const char *file, int line,
                        const char *format, va_list arguments)
{
    char timestamp[LOGGER_TIMESTAMP_SIZE];
    FILE *output;
    bool use_color;

    if (format == NULL || level < LOG_LEVEL_DEBUG || level > LOG_LEVEL_ERROR)
        return;
    pthread_mutex_lock(&g_logger.mutex);
    if (level < g_logger.level)
    {
        pthread_mutex_unlock(&g_logger.mutex);
        return;
    }
    output = g_logger.output != NULL ? g_logger.output : stderr;
    use_color = g_logger.color_was_set
        ? g_logger.color : isatty(fileno(output));
    format_timestamp(timestamp);
    if (use_color)
        fputs(level_color(level), output);
    fprintf(output, "[%s] [%-7s] ", timestamp, level_name(level));
    if (file != NULL)
        fprintf(output, "[%s:%d] ", base_name(file), line);
    vfprintf(output, format, arguments);
    if (use_color)
        fputs("\033[0m", output);
    fputc('\n', output);
    fflush(output);
    pthread_mutex_unlock(&g_logger.mutex);
}

void logger_log(t_log_level level, const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    logger_vlog(level, NULL, 0, format, arguments);
    va_end(arguments);
}

void logger_log_at(t_log_level level, const char *file, int line,
                   const char *format, ...)
{
    va_list arguments;

    va_start(arguments, format);
    logger_vlog(level, file, line, format, arguments);
    va_end(arguments);
}
