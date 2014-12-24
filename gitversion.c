#include "gitversion.h"
#include "log.h"

const char *gitversion = GITVERSION;

void print_version()
{
    log_printf(L_INFO, "Tuntox built from git commit %s", gitversion);
}
