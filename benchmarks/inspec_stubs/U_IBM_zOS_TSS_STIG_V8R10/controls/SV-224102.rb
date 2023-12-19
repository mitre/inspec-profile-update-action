control 'SV-224102' do
  title 'The IBM z/OS UNIX Telnet server Startup parameters must be properly specified.'
  desc 'Display of a standardized and approved use notification before granting access to the operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.

System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.'
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
  ref 'DPMS Target IBM zOS TSS'
  tag check_id: 'C-25775r516705_chk'
  tag severity: 'medium'
  tag gid: 'V-224102'
  tag rid: 'SV-224102r877942_rule'
  tag stig_id: 'TSS0-UT-000040'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25763r516706_fix'
  tag 'documentable'
  tag legacy: ['V-98911', 'SV-108015']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
