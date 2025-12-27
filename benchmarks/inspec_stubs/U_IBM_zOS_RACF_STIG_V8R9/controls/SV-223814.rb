control 'SV-223814' do
  title 'The IBM z/OS Syslog daemon must be properly defined and secured.'
  desc 'The Syslog daemon, known as syslogd, is a zOS UNIX daemon that provides a central processing point for log messages issued by other zOS UNIX processes. It is also possible to receive log messages from other network-connected hosts. Some of the IBM Communications Server components that may send messages to syslog are the FTP, TFTP, zOS UNIX Telnet, DNS, and DHCP servers. The messages may be of varying importance levels including general process information, diagnostic information, critical error notification, and audit-class information. Primarily because of the potential to use this information in an audit process, there is a security interest in protecting the syslogd process and its associated data. 

The Syslog daemon requires special privileges and access to sensitive resources to provide its system services. Failure to properly define and control the Syslog daemon could lead to unauthorized access. This exposure may result in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.'
  desc 'check', "From z/OS command screen enter: 
ListUser SYSLOGD OMVS (SYSLOGD is usual name of the SYSLOG daemon)

If all of the following are true, this is not a finding.

If either of the following is untrue, this is a finding.

-The SYSLOGD userid is defined as a PROTECTED userid.
-The SYSLOGD userid has the following z/OS UNIX attributes: UID(0), HOME directory '/', shell program /bin/sh.

From z/OS command screen enter:
RList STARTED SYSLOGD

If a matching entry in the STARTED resource class exists enabling the use of the standard userid and appropriate group, this is not a finding."
  desc 'fix', "The Syslog daemon userid is SYSLOGD.
Define the SYSLOGD userid as a PROTECTED userid.
Define the SYSLOGD userid has UID(0), HOME('/'), and PROGRAM('/bin/sh') specified in the OMVS segment.

To set up and use as an MVS Started Proc, the following sample commands are provided:

AU SYSLOGD NAME('stc, tcpip') NOPASSWORD NOOIDCARD DFLTGRP(STC) -
OWNER(STC) DATA('Reference ISLG0020 for proper setup ')
ALU SYSLOGD DFLTGRP(stctcpx) 
ALU SYSLOGD OMVS(UID(0) HOME('/') PROGRAM('/bin/sh')) 
CO SYSLOGD GROUP(stctcpx) OWNER(stctcpx)

A matching entry mapping the SYSLOGD started proc to the SYSLOGD userid is in the STARTED resource class.

RDEF STARTED SYSLOGD.** UACC(NONE) OWNER(ADMIN) AUDIT(ALL(READ)) STDATA(USER(SYSLOGD) GROUP(STC)) 

If /etc/rc is used to start the Syslog daemon, ensure that the _BPX_JOBNAME and _BPX_ USERID environment variables are assigned a value of SYSLOGD."
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25487r868863_chk'
  tag severity: 'medium'
  tag gid: 'V-223814'
  tag rid: 'SV-223814r868865_rule'
  tag stig_id: 'RACF-SL-000030'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25475r868864_fix'
  tag 'documentable'
  tag legacy: ['V-98335', 'SV-107439']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
