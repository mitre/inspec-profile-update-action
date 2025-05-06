control 'SV-223848' do
  title 'IBM z/OS UNIX SYSTEM FILE SECURITY SETTINGS must be properly protected or specified.'
  desc 'If the operating system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

'
  desc 'check', 'From the ISPF Command Shell enter:
OMVS

For each file listed in the table below enter:
ls -alW /<directory name>/<file name>

If the HFS permission bits and user audit bits for each directory and file match or are more restrictive than the specified settings listed in the table, this is not a finding.

NOTE: Some of the files listed are not used in every configuration. Absence of any of the files is not considered a finding.

 SYSTEM FILE SECURITY SETTINGS
FILE PERMISSION BITS USER AUDIT BITS FUNCTION
/bin/sh 1755 faf z/OS UNIX shell
 Note: /bin/sh has the sticky bit on to improve performance.
/dev/console 740 fff The system console file receives messages that may require System Administrator (SA) attention.
/dev/null 666 fff A null file; data written to it is discarded.
/etc/auto.master
any mapname files 740 faf Configuration files for automount facility
/etc/inetd.conf 740 faf Configuration file for network services
/etc/init.options 740 faf Kernel initialization options file for z/OS UNIX environment
/etc/log 744 fff Kernel initialization output file
/etc/profile 755 faf Environment setup script executed for each user
/etc/rc 744 faf Kernel initialization script for z/OS UNIX environment
/etc/steplib 740 faf List of MVS data sets valid for set user ID and set group ID executables
/etc/tablename 740 faf List of z/OS userids and group names with corresponding alias names
/usr/lib/cron/at.allow
/usr/lib/cron/at.deny 700 faf Configuration files for the at and batch commands
/usr/lib/cron/cron.allow
/usr/lib/cron/cron.deny 700 faf Configuration files for the crontab command

NOTE: Some of the files listed are not used in every configuration. Absence of any of the files is not considered a finding.

NOTE: The names of the MapName files are site-defined. Refer to the listing in the EAUTOM report.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:

f log for failed access attempts
a log for failed and successful access
- no auditing'
  desc 'fix', 'Define the UNIX permission bits and user audit bits on the HFS files as listed in the table below.

 SYSTEM FILE SECURITY SETTINGS
FILE PERMISSION BITS USER AUDIT BITS FUNCTION
/bin/sh 1755 faf z/OS UNIX shell
 Note: /bin/sh has the sticky bit on to improve performance.
/dev/console 740 fff The system console file receives messages that may require System Administrator (SA) attention.
/dev/null 666 fff A null file; data written to it is discarded.
/etc/auto.master
any mapname files 740 faf Configuration files for automount facility
/etc/inetd.conf 740 faf Configuration file for network services
/etc/init.options 740 faf Kernel initialization options file for z/OS UNIX environment
/etc/log 744 fff Kernel initialization output file
/etc/profile 755 faf Environment setup script executed for each user
/etc/rc 744 faf Kernel initialization script for z/OS UNIX environment
/etc/steplib 740 faf List of MVS data sets valid for set user ID and set group ID executables
/etc/tablename 740 faf List of z/OS userids and group names with corresponding alias names
/usr/lib/cron/at.allow
/usr/lib/cron/at.deny 700 faf Configuration files for the at and batch commands
/usr/lib/cron/cron.allow
/usr/lib/cron/cron.deny 700 faf Configuration files for the crontab command

There are a number of files that must be secured to protect system functions in z/OS UNIX. Where not otherwise specified, these files must receive a permission setting of 744 or 774. The 774 setting may be used at the site’s discretion to help to reduce the need for assignment of superuser privileges. The table identifies permission bit and audit bit settings that are required for these specific files. More restrictive permission settings may be used at the site’s discretion or as specific environments dictate.

The following represents a hierarchy for permission bits from least restrictive to most restrictive:

7 rwx (least restrictive)
6 rw-
3 -wx
2 -w-
5 r-x
4 r--
1 --x
0 --- (most restrictive)

The possible audit bits settings are as follows:

f log for failed access attempts
a log for failed and successful access
- no auditing

The following commands are a sample of the commands to be used (from a user account with an effective UID(0)) to update the permission bits and audit bits:

chmod 1755 /bin/sh
chaudit w=sf,rx+f /bin/sh
chmod 0740 /dev/console
chaudit rwx=f /dev/console'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25521r515232_chk'
  tag severity: 'medium'
  tag gid: 'V-223848'
  tag rid: 'SV-223848r604139_rule'
  tag stig_id: 'RACF-US-000110'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25509r515233_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000259-GPOS-00100']
  tag 'documentable'
  tag legacy: ['V-98403', 'SV-107507']
  tag cci: ['CCI-000213', 'CCI-001499']
  tag nist: ['AC-3', 'CM-5 (6)']
end
