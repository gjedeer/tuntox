#ifndef _MACH_H
#define _MACH_H

#include <time.h>
#include <mach/mach_time.h>

// there is no CLOCK_REALTIME or CLOCK_MONOTONIC on MacOS platform
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 0

// MacOS doesn't support the flag MSG_NOSIGNAL
#define MSG_NOSIGNAL SO_NOSIGPIPE

#endif