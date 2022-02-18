#ifndef _MACH_H
#define _MACH_H

#include <time.h>
#include <mach/mach_time.h>

// MacOS doesn't support the flag MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE

#endif
