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
