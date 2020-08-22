#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "log.h"

/*
 * The minimum log level; set to one of L_* constants from log.h
 */
int min_log_level = 666;

/*
 * 0: send output to stderr
 * 1: send output to syslog LOG_LOCAL1 facility
 */
int use_syslog = 0;

/*
 * 0: don't display toxcore TRACE messages
 * 1: display all toxcore messages
 */
int log_tox_trace = 0;

/* Turn log level number to a printable string */
char *log_printable_level(int level)
{
    switch(level)
    {
        case L_ERROR:
            return "ERROR";
        case L_WARNING:
            return "WARNING";
        case L_NOTICE:
            return "NOTICE";
        case L_INFO:
            return "INFO";
        case L_DEBUG:
            return "DEBUG";
        case L_DEBUG2:
            return "DEBUG2";
        case L_DEBUG3:
            return "DEBUG3";
        case L_DEBUG4:
            return "DEBUG4";
        case L_DEBUG5:
            return "DEBUG5";
    }
    return "UNKNOWN";
}

void log_init(void)
{
    if(use_syslog)
    {
        openlog("tuntox", LOG_PID, LOG_LOCAL1);
    }
}

void log_close(void)
{
    if(use_syslog)
    {
        closelog();
    }
}

/* Output the log to the console */
void log_printf(int level, const char *fmt, ...)
{
    va_list args;
    char logfmt[2048];
    char logtime[100];
    char *level_str;
    time_t rawtime;
    struct tm *timeinfo;

    if(level > min_log_level)
    {
        return;
    }

    if(!use_syslog)
    {
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(logtime, 100, "%F %X", timeinfo);

        level_str = log_printable_level(level);

        if(fmt[strlen(fmt)-1] == '\n')
        {
            snprintf(logfmt, 2048, "%s: [%s]\t%s", logtime, level_str, fmt);
        }
        else
        {
            snprintf(logfmt, 2048, "%s: [%s]\t%s\n", logtime, level_str, fmt);
        }

        va_start(args, fmt);
        vfprintf(stderr, logfmt, args);
        va_end(args);
    }
    else
    {
        va_start(args, fmt);
        vsyslog(LOG_MAKEPRI(LOG_LOCAL1, level), fmt, args);
        va_end(args);
    }
}


void log_test(void)
{
    int i = 112;
    char *x = "test";

    log_printf(L_WARNING, "Testing");
    log_printf(L_ERROR, "Number stodwadziesciatrzy: %d", 123);
    d(beenthere);
    dd(i);

    dp(&i);
    ds(x);
}

static const char *tox_log_level_name(TOX_LOG_LEVEL level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "ERROR";
    }

	return "UNKNOWN";
}

void on_tox_log(Tox *tox, TOX_LOG_LEVEL level, const char *path, uint32_t line, const char *func,
		const char *message, void *user_data)
{
    uint32_t index = user_data ? *(uint32_t *)user_data : 0;
    const char *file = strrchr(path, '/');

	if(level == TOX_LOG_LEVEL_TRACE && !log_tox_trace)
	{
		return;
	}

    file = file ? file + 1 : path;
    log_printf(L_DEBUG2, "[#%d] %s %s:%d\t%s:\t%s\n", index, tox_log_level_name(level), file, line, func, message);
}
