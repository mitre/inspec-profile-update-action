control 'SV-38719' do
  title 'The system must not have the rusersd service active.'
  desc 'The rusersd daemon gives out a list of current uses on the system.   The rusersd daemon is unnecessary and it increases the attack vector of the system by providing information on the current users of the system.'
  desc 'check', 'Check the /etc/inetd.conf file for active rusersd service.

#grep rusersd /etc/inetd.conf | grep -v \\#

If the rusersd service is enabled,  this is a finding.'
  desc 'fix', 'Edit the /etc/inetd.conf file and comment out the rusersd service line. 

Restart the inetd service.   

# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37815r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29515'
  tag rid: 'SV-38719r1_rule'
  tag stig_id: 'GEN009310'
  tag gtitle: 'GEN009310'
  tag fix_id: 'F-33073r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
