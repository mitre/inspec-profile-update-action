control 'SV-38712' do
  title 'The system must not have Internet Message Access Protocol (IMAP) service active.'
  desc 'The IMAP service should not be running unless the system is acting as a mail server for client connections.   Running unnecessary services increases the attack vector on the system.'
  desc 'check', 'Check the /etc/inetd.conf file for active IMAP service.

#grep imapd /etc/inetd.conf | grep -v \\#

If the IMAP service is enabled, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the imap2 service line. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37808r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29508'
  tag rid: 'SV-38712r1_rule'
  tag stig_id: 'GEN009240'
  tag gtitle: 'GEN009240'
  tag fix_id: 'F-33066r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
