control 'SV-224089' do
  title 'IBM z/OS UNIX security parameters in /etc/rc must be properly specified.'
  desc 'Configuration settings are the set of parameters that can be changed in hardware, software, or firmware components of the system that affect the security posture and/or functionality of the system. Security-related parameters are those parameters impacting the security state of the system, including the parameters required to satisfy other security control requirements. Security-related parameters include, for example: registry settings; account, file, directory permission settings; and settings for functions, ports, protocols, services, and remote connections.'
  desc 'check', 'From the ISPF Command Shell enter:
ISHELL
/etc/rc

If all of the CHMOD commands in /etc/rc do not result in less restrictive access than what is specified in the tables below this is not a finding.

NOTE: The use of CHMOD commands in /etc/rc is required in most environments to comply with the required settings, especially for dynamic objects such as the /dev directory.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

If all of the CHAUDIT commands in /etc/rc do not result in less auditing than what is specified in the tables below this is not a finding.

NOTE: The use of CHAUDIT commands in /etc/rc may not be necessary. If none are found, there is not a finding.

The possible audit bits settings are as follows:

f log for failed access attempts
a log for failed and successful access
- no auditing

If the _BPX_JOBNAME variable is appropriately set (i.e., to match daemon name) as each daemon (e.g., syslogd, inetd) is started in /etc/rc, this is not a finding.

NOTE: If _BPX_JOBNAME is not specified, the started address space will be named using an inherited value. This could result in reduced security in terms of operator command access.

 SYSTEM DIRECTORY SECURITY SETTINGS
DIRECTORY PERMISSION BITS USER AUDIT BITS FUNCTION
/ [root] 755 faf Root level of all file systems. Holds critical mount points.
/bin 1755 fff Shell scripts and executables for basic functions
/dev 1755 fff Character-special files used when logging into the OMVS shell and during C language program compilation.
 Files are created during system IPL and on a per-demand basis.
/etc 1755 faf Configuration programs and files (usually with locally customized data) used by z/OS UNIX and other product initialization processes
/lib 1755 fff System libraries including dynamic link libraries and files for static linking
/samples 1755 fff Sample configuration and other files
/tmp 1777 fff Temporary data used by daemons, servers, and users. Note: /tmp must have the sticky bit on to restrict file renames and deletions.
/u 1755 fff Mount point for user home directories and optionally for third-party software and other local site files
/usr 1755 fff Shell scripts, executables, help (man) files and other data. Contains sub-directories (e.g., lpp) and mount points used by program products that may be in separate file systems.
/var 1775 fff Dynamic data used internally by products and by elements and features of z/OS UNIX.

 SYSTEM FILE SECURITY SETTINGS
FILE PERMISSION BITS USER AUDIT BITS FUNCTION
/bin/sh 1755 faf z/OS UNIX shell
 Note: /bin/sh has the sticky bit on to improve performance.
/dev/console 740 fff The system console file receives messages that may require System Administrator (SA) attention.
/dev/null 666 fff A null file; data written to it is discarded.
/etc/auto.master and
any mapname files 740 faf Configuration files for automount facility
/etc/inetd.conf 740 faf Configuration file for network services
/etc/init.options 740 faf Kernel initialization options file for z/OS UNIX environment
/etc/log 744 fff Kernel initialization output file
/etc/profile 755 faf Environment setup script executed for each user
/etc/rc 744 faf Kernel initialization script for z/OS UNIX environment
/etc/steplib 740 faf List of MVS data sets valid for set user ID and set group ID executables
/etc/table name 740 faf List of z/OS userids and group names with corresponding alias names
/usr/lib/cron/at.allow
/usr/lib/cron/at.deny 700 faf Configuration files for the at and batch commands
/usr/lib/cron/cron.allow
/usr/lib/cron/cron.deny 700 faf Configuration files for the crontab command'
  desc 'fix', 'Review the settings in the /etc/rc. The /etc/rcfile is the system initialization shell script. When z/OS UNIX kernel services start, /etc/rc is executed to set file permissions and ownership for dynamic system files and to perform other system startup functions such as starting daemons. There can be many commands in /etc/rc. There are two specific guidelines that must be followed:

Verify that The CHMOD or CHAUDIT command does not result in less restrictive security than what is specified in the table in the z/OS UNIX System Services Planning, Establishing UNIX security under the SYSTEM DIRECTORY SECURITY SETTINGS. 

Immediately prior to each command that starts a daemon, the _BPX_JOBNAME variable must be set to match the daemon’s name (e.g., inetd, syslogd). The use of _BPX_USERID is at the site’s discretion, but is recommended.'
  impact 0.5
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25762r516666_chk'
  tag severity: 'medium'
  tag gid: 'V-224089'
  tag rid: 'SV-224089r561402_rule'
  tag stig_id: 'TSS0-US-000160'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25750r516667_fix'
  tag 'documentable'
  tag legacy: ['V-98885', 'SV-107989']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
