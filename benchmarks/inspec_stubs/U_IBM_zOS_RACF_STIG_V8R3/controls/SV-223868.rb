control 'SV-223868' do
  title 'The IBM z/OS UNIX Telnet server warning banner must be properly specified.'
  desc 'Display of a standardized and approved use notification before granting access to the publicly accessible operating system ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.'
  desc 'check', 'From the ISPF Command Shell enter:
ISHELL

Enter /etc/ for a pathname - you may need to issue a CD /etc/
select FILE NAME inetd.conf

If Option -h is included on the otelnetd command, this is a finding.'
  desc 'fix', 'Configure the startup parameters in the inetd.conf file for otelnetd to exclude option -h.
Note: -h indicates that the logon banner should not be displayed.'
  impact 0.5
  ref 'DPMS Target IBM zOS RACF'
  tag check_id: 'C-25541r515292_chk'
  tag severity: 'medium'
  tag gid: 'V-223868'
  tag rid: 'SV-223868r604139_rule'
  tag stig_id: 'RACF-UT-000050'
  tag gtitle: 'SRG-OS-000228-GPOS-00088'
  tag fix_id: 'F-25529r515293_fix'
  tag 'documentable'
  tag legacy: ['V-98443', 'SV-107547']
  tag cci: ['CCI-001388', 'CCI-001386', 'CCI-001387', 'CCI-001384', 'CCI-001385']
  tag nist: ['AC-8 c 3', 'AC-8 c 2', 'AC-8 c 2', 'AC-8 c 1', 'AC-8 c 2']
end
