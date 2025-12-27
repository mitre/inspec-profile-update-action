control 'SV-223592' do
  title 'IBM z/OS Syslog daemon must be properly defined and secured.'
  desc 'The Syslog daemon, known as syslogd, is a zOS UNIX daemon that provides a central processing point for log messages issued by other zOS UNIX processes. It is also possible to receive log messages from other network-connected hosts. Some of the IBM Communications Server components that may send messages to syslog are the FTP, TFTP, zOS UNIX Telnet, DNS, and DHCP servers. The messages may be of varying importance levels including general process information, diagnostic information, critical error notification, and audit-class information. Primarily because of the potential to use this information in an audit process, there is a security interest in protecting the syslogd process and its associated data. 

The Syslog daemon requires special privileges and access to sensitive resources to provide its system services. Failure to properly define and control the Syslog daemon could lead to unauthorized access. This exposure may result in the compromise of the integrity and availability of the operating system environment, ACP, and customer data.'
  desc 'check', 'The syslog daemon is defined as SYSLOGD.

From the ACF command screen enter:
SET LID
LIST SYSLOGD

If the Syslog daemon is not defined, this is a finding.

If the SYSLOGD logonid is not defined with the STC attribute, this is a finding.

If the SYSLOGD userid has UID(0), HOME(‘/’), and PROGRAM(‘/bin/sh’) specified in the OMVS segment, this is not a finding. 

If Syslog daemon is started from /etc/rc then ensure that the _BPX_JOBNAME and _BPX_USERID environment variables are assigned a value of SYSLOGD.'
  desc 'fix', "Define the Syslog daemon logonid as SYSLOGD with the STC attribute.

To set up and use as an MVS Started Proc, the following sample commands are provided:
SET LID
INSERT SYSLOGD NAME(SYSLOGD STC) GROUP(stctcpx) STC

The SYSLOGD userid has UID(0), HOME('/'), and PROGRAM('/bin/sh') specified in the OMVS segment.

SET PROFILE(USER) DIVISION(OMVS)
INSERT SYSLOGD UID(0) HOME(/) PROGRAM(/bin/sh)

F ACF2,REBUILD(USR),CLASS(P)

If /etc/rc is used to start the Syslog daemon ensure that the _BPX_JOBNAME and _BPX_ USERID environment variables are assigned a value of SYSLOGD."
  impact 0.5
  ref 'DPMS Target IBM zOS ACF2'
  tag check_id: 'C-25265r504749_chk'
  tag severity: 'medium'
  tag gid: 'V-223592'
  tag rid: 'SV-223592r533198_rule'
  tag stig_id: 'ACF2-SL-000030'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-25253r504750_fix'
  tag 'documentable'
  tag legacy: ['V-97889', 'SV-106993']
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']
end
