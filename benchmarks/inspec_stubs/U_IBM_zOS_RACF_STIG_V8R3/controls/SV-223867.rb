control 'SV-223867' do
  title 'IBM z/OS UNIX Telnet server Startup parameters must be properly specified.'
  desc 'The z/OS UNIX Telnet Server (i.e., otelnetd) provides interactive access to the z/OS UNIX shell. During the initialization process, startup parameters are read to define the characteristics of each otelnetd instance. Some of these parameters have an impact on system security. Failure to specify the appropriate command options could result in degraded security. This exposure may result in unauthorized access impacting data integrity or the availability of some system services.'
  desc 'check', 'From the ISPF Command Shell enter:
ISHELL

Enter /etc/ for a pathname - you may need to issue a CD /etc/
select FILE NAME inetd.conf

If Option -D login is included on the otelnetd command, this is not a finding.

If Option -c 900 is included on the otelnetd command, this is not a finding.

NOTE: "900" indicates a session timeout value of "15" minutes and is currently the maximum value allowed.'
  desc 'fix', 'Configure the startup parameters in the inetd.conf file for otelnetd to conform to the specifications below.

The otelnetd startup command includes the options -D login and -c 900, where:

-D login indicates that messages should be written to the syslogd facility for login and logout activity.

-c 900 indicates that the Telnet session should be terminated after "15" minutes of inactivity.

NOTE: "900" is the maximum value; any value between "1" and "900" is acceptable.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25540r515289_chk'
  tag severity: 'medium'
  tag gid: 'V-223867'
  tag rid: 'SV-223867r604139_rule'
  tag stig_id: 'RACF-UT-000040'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25528r515290_fix'
  tag 'documentable'
  tag legacy: ['V-98441', 'SV-107545']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
