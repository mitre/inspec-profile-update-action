control 'SV-38713' do
  title 'The system must not have the PostOffice Protocol (POP3) service active.'
  desc "The POP3 service is only needed if the server is acting as a mail server and clients are using applications that only support POP3.  Users' ids and passwords are sent in plain text to the POP3 service.  If mail client access is needed,  consider using IMAP or SSL enabled POP3."
  desc 'check', "Check the '/etc/inetd.conf' file for active POP3 service.

#grep pop3 /etc/inetd.conf | grep -v \\#

If the POP3 service is enabled,  this is a finding."
  desc 'fix', 'Edit /etc/inetd.conf and comment out POP3 the service line. Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37809r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29509'
  tag rid: 'SV-38713r1_rule'
  tag stig_id: 'GEN009250'
  tag gtitle: 'GEN009250'
  tag fix_id: 'F-33067r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
