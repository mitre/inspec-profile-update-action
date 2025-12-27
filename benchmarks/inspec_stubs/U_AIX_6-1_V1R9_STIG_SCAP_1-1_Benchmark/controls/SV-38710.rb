control 'SV-38710' do
  title 'The system must not have the dtspc service active.'
  desc 'This service is started automatically by the inetd daemon with root permission in response to a CDE client requesting a process to be started on the daemon’s host system.   Running the dtscp service is unnecessary and it increases the attack vector of the system.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out dtspc service line. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29506'
  tag rid: 'SV-38710r1_rule'
  tag stig_id: 'GEN009220'
  tag gtitle: 'GEN009220'
  tag fix_id: 'F-33064r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
