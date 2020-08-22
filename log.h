#include <tox/tox.h>

#define L_ERROR 	3
#define L_WARNING	4
#define L_NOTICE	5
#define L_INFO		6
#define L_DEBUG		7
#define L_DEBUG2	8
#define L_DEBUG3	9
#define L_DEBUG4	10
#define L_DEBUG5	11

#define L_UNSET		0x29a

void log_printf(int level, const char *fmt, ...);
void log_init(void);
void log_close(void);
void on_tox_log(Tox *tox, TOX_LOG_LEVEL level, const char *file, uint32_t line, const char *func,
		const char *message, void *user_data);

extern int min_log_level;
extern int use_syslog;
extern int log_tox_trace;

#define d(x) log_printf(L_DEBUG, "%s:%d %s", __FILE__, __LINE__, #x);

/* Debug-log the int variable x */
#define dd(x) log_printf(L_DEBUG, "%s:%d %s=%d", __FILE__, __LINE__, #x, (x));

/* Debug-log the pointer variable x */
#define dp(x) log_printf(L_DEBUG, "%s:%d %s=%p", __FILE__, __LINE__, #x, (x));

/* Debug-log the string variable x */
#define ds(x) log_printf(L_DEBUG, "%s:%d %s=%s", __FILE__, __LINE__, #x, (x));
