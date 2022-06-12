#include <stdio.h>
#include "gitversion.h"
#include "log.h"

const char *gitversion = GITVERSION;

void print_version()
{
    log_printf(L_INFO, "Tuntox built from git commit %s, toxcore version %d.%d.%d", gitversion, tox_version_major(), tox_version_minor(), tox_version_patch());
}

void print_version_stdout()
{
    printf("Tuntox built from git commit %s, toxcore version %d.%d.%d\n", gitversion, tox_version_major(), tox_version_minor(), tox_version_patch());
}
