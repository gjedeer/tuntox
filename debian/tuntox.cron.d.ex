#
# Regular cron jobs for the tuntox package
#
0 4	* * *	root	[ -x /usr/bin/tuntox_maintenance ] && /usr/bin/tuntox_maintenance
