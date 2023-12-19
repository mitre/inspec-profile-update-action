control 'SV-38709' do
  title 'The system must not have the discard service active.'
  desc 'The discard service runs as root from the inetd server and can be used in Denial of Service attacks.   The discard  service is unnecessary and it increases the attack vector of the system.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the discard service line for both TCP and UDP protocols. 
Restart the inetd service.
#refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29505'
  tag rid: 'SV-38709r1_rule'
  tag stig_id: 'GEN009210'
  tag gtitle: 'GEN009210'
  tag fix_id: 'F-33063r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
