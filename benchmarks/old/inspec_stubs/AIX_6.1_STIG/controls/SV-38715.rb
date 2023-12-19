control 'SV-38715' do
  title 'The system must not have the netstat service active on the inetd process.'
  desc 'The netstat service can potentially give out network information on active connections if it is running.  The information given out can aid in an attack and weaken the systems defensive posture.'
  desc 'check', 'Check the /etc/inetd.conf for active netstat service.

grep netstat /etc/inetd.conf | grep -v \\#

If the netstat service is active,  this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the netstat service line. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37811r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29511'
  tag rid: 'SV-38715r1_rule'
  tag stig_id: 'GEN009270'
  tag gtitle: 'GEN009270'
  tag fix_id: 'F-33069r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
