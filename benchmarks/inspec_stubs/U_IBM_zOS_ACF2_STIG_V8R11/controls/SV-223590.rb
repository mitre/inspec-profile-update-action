control 'SV-223590' do
  title 'IBM z/OS permission bits and user audit bits for HFS objects that are part of the Syslog daemon component must be configured properly.'
  desc 'HFS directories and files of the Syslog daemon provide the configuration and executable properties of this product. Failure to properly secure these objects could lead to unauthorized access. This exposure may result in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.'
  desc 'check', "From an ISPF enter:
cd /usr/sbin
Enter
ls -alW

If File Permission Bits and User Audit Bits for SYSLOG Daemon HFS directories and files is as below, this is not a finding.

/usr/sbin/syslogd 1740 fff

Enter:
cd /etc/
Enter
ls -alW

If the file Permission Bits and User Audit Bits for Output log file defined in the configuration file are as below, this is not a finding.

/etc/syslog.conf 0744 faf
0744 fff

Notes:
The /usr/sbin/syslogd object is a symbolic link to /usr/lpp/tcpip/sbin/syslogd. The permission and user audit bits on the target of the symbolic link must have the required settings.

The /etc/syslog.conf file may not be the configuration file the daemon uses. It is necessary to check the script or JCL used to start the daemon to determine the actual configuration file. For example, in /etc/rc:
_BPX_JOBNAME='SYSLOGD' /usr/sbin/syslogd -f /etc/syslog.conf

For example, in the SYSLOGD started task JCL:

//SYSLOGD EXEC PGM=SYSLOGD,REGION=30M,TIME=NOLIMIT 
//PARM='POSIX(ON) ALL31(ON)/ -f /etc/syslogd.conf'

//SYSLOGD EXEC PGM=SYSLOGD,REGION=30M,TIME=NOLIMIT 
//PARM='POSIX(ON) ALL31(ON) /-f //''SYS1.TCPPARMS(SYSLOG)'''

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
- no auditing"
  desc 'fix', "With the assistance of a systems programmer with UID(0) and/or SUPERUSER access, review the UNIX permission bits and user audit bits on the HFS directories and files for the Syslog daemon. Ensure they conform to the specifications in the SYSLOG Daemon HFS Object Security Settings table below.

Log files should have security that prevents anyone except the syslogd process and authorized maintenance jobs from writing to or deleting them. 

A maintenance process to periodically clear the log files is essential. Logging stops if the target file system becomes full.

SYSLOG Daemon HFS Object Security Settings
File Permission Bits User Audit Bits
/usr/sbin/syslogd 1740 fff
[Configuration File]
/etc/syslog.conf 0744 faf
[Output log file defined in the configuration file]
0744 fff

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

NOTES:
The /usr/sbin/syslogd object is a symbolic link to /usr/lpp/tcpip/sbin/syslogd. The permission and user audit bits on the target of the symbolic link must have the required settings.

The /etc/syslog.conf file may not be the configuration file the daemon uses. It is necessary to check the script or JCL used to start the daemon to determine the actual configuration file. For example, in /etc/rc:

_BPX_JOBNAME='SYSLOGD' /usr/sbin/syslogd -f /etc/syslog.conf

For example, in the SYSLOGD started task JCL:

//SYSLOGD EXEC PGM=SYSLOGD,REGION=30M,TIME=NOLIMIT 
//PARM='POSIX(ON) ALL31(ON)/ -f /etc/syslogd.conf'

//SYSLOGD EXEC PGM=SYSLOGD,REGION=30M,TIME=NOLIMIT 
//PARM='POSIX(ON) ALL31(ON) /-f //''SYS1.TCPPARMS(SYSLOG)'''

The following commands can be used (from a user account with an effective UID(0)) to update the permission bits and audit bits:

chmod 1740 /usr/lpp/tcpip/sbin/syslogd
chaudit rwx=f /usr/lpp/tcpip/sbin/syslogd
chmod 0744 /etc/syslog.conf
chaudit w=sf,rx+f /etc/syslog.conf
chmod 0744 /log_dir/log_file
chaudit rwx=f /log_dir/log_file"
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25263r504743_chk'
  tag severity: 'medium'
  tag gid: 'V-223590'
  tag rid: 'SV-223590r533198_rule'
  tag stig_id: 'ACF2-SL-000010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-25251r504744_fix'
  tag 'documentable'
  tag legacy: ['V-97885', 'SV-106989']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
