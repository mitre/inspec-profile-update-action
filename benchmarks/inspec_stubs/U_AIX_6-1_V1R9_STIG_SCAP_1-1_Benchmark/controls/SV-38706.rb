control 'SV-38706' do
  title 'The system must not have the tool-talk database server (ttdbserver) service active.'
  desc 'The ttdbserver service for CDE is an unnecessary service that runs as root and might be compromised.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out ttdbserver service line. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29502'
  tag rid: 'SV-38706r1_rule'
  tag stig_id: 'GEN009180'
  tag gtitle: 'GEN009180'
  tag fix_id: 'F-33060r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
