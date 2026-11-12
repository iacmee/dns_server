#ifndef LOGGER_H
#define LOGGER_H

#include <stdbool.h>
#include <stdio.h>

typedef enum e_log_level
{
    LOG_LEVEL_DEBUG = 0,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_NONE
} t_log_level;

/*
 * Configuration is process-wide. By default logs are written to stderr,
 * DEBUG messages are enabled and colors are used only on a terminal.
 */
void logger_set_level(t_log_level level);
void logger_set_output(FILE *output);
void logger_set_color(bool enabled);

void logger_log(t_log_level level, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
void logger_log_at(t_log_level level, const char *file, int line,
                   const char *format, ...)
    __attribute__((format(printf, 4, 5)));

#define LOG_DEBUG(...) logger_log(LOG_LEVEL_DEBUG, __VA_ARGS__)
#define LOG_INFO(...) logger_log(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARNING(...) logger_log(LOG_LEVEL_WARNING, __VA_ARGS__)
#define LOG_ERROR(...) logger_log(LOG_LEVEL_ERROR, __VA_ARGS__)

#define LOG_DEBUG_AT(...) \
    logger_log_at(LOG_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_INFO_AT(...) \
    logger_log_at(LOG_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_WARNING_AT(...) \
    logger_log_at(LOG_LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define LOG_ERROR_AT(...) \
    logger_log_at(LOG_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)

#endif
