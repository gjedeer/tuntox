#include "gitversion.h"
#include "log.h"

const char *gitversion = GITVERSION;

void print_version()
{
    log_printf(L_INFO, "tuntox built from git commit %s", gitversion);
}
