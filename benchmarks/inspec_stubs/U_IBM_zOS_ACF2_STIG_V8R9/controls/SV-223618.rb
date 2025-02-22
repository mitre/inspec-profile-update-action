control 'SV-223618' do
  title 'IBM z/OS UNIX security parameters in /etc/rc must be properly specified.'
  desc 'Configuring the operating system to implement organization-wide security implementation guides and security checklists ensures compliance with federal standards and establishes a common security baseline across DoD that reflects the most restrictive security posture consistent with operational requirements.'
  desc 'check', 'From the ISPF COMMAND SHELL enter:
ISHELL
/etc/rc

If all of the CHMOD commands in /etc/rc do not result in less restrictive access than what is specified in the tables below, this is not a finding.

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

Directory      Permission Bits     User Audit Bits   Function
/ [root]       755                 faf                Root level of all file systems. Holds critical mount points.
/bin           1755                fff                Shell scripts and executables for basic functions
/dev           1755                fff                 Character-special files used when logging into the OMVS shell and during C language program compilation. Files are created during system IPL and on a per-demand basis.
/etc           1755               faf                Configuration programs and files (usually with locally customized data) used by z/OS UNIX and other product initialization processes
/lib           1755               fff               System libraries including dynamic link libraries and files for static linking
/samples       1755               fff               Sample configuration and other files
/tmp           1777               fff               Temporary data used by daemons, servers, and users. Note: /tmp must have the sticky bit on to restrict file renames and deletions.
/u             1755               fff               Mount point for user home directories and optionally for third-party software and other local site files
/usr           1755               fff               Shell scripts, executables, help (man) files and other data. Contains sub-directories (e.g., lpp) and mount points used by program products that may be in separate file systems.
/var           1775               fff               Dynamic data used internally by products and by elements and features of z/OS UNIX.'
  desc 'fix', "Review the settings in the /etc/rc. The /etc/rcfile is the system initialization shell script. When z/OS UNIX kernel services start, /etc/rc is executed to set file permissions and ownership for dynamic system files and to perform other system startup functions such as starting daemons. There can be many commands in /etc/rc. 

There are two specific guidelines that must be followed:
-Verify that the CHMOD or CHAUDIT command does not result in less restrictive security than what is specified in the table below.
-Immediately prior to each command that starts a daemon, the _BPX_JOBNAME variable must be set to match the daemon's name (e.g., inetd, syslogd). The use of _BPX_USERID is at the site's discretion, but is recommended.

Directory    Permission Bits    User Audit Bits    Function
/ [root]     755                faf                Root level of all file systems. Holds critical mount points.
/bin         1755               fff                Shell scripts and executables for basic functions
/dev         1755               fff                Character-special files used when logging into the OMVS shell and during C language program compilation. Files are created during system IPL and on a per-demand basis.
/etc         1755               faf               Configuration programs and files (usually with locally customized data) used by z/OS UNIX and other product initialization processes
/lib         1755               fff                System libraries including dynamic link libraries and files for static linking
/samples     1755               fff                Sample configuration and other files
/tmp         1777               fff                Temporary data used by daemons, servers, and users. Note: /tmp must have the sticky bit on to restrict file renames and deletions.
/u           1755               fff                Mount point for user home directories and optionally for third-party software and other local site files
/usr         1755               fff                Shell scripts, executables, help (man) files and other data. Contains sub-directories (e.g., lpp) and mount points used by program products that may be in separate file systems.
/var         1775               fff                Dynamic data used internally by products and by elements and features of z/OS UNIX."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25291r504812_chk'
  tag severity: 'medium'
  tag gid: 'V-223618'
  tag rid: 'SV-223618r861186_rule'
  tag stig_id: 'ACF2-US-000030'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25279r858896_fix'
  tag 'documentable'
  tag legacy: ['SV-107045', 'V-97941']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
