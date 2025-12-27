control 'SV-38708' do
  title 'The system must not have the daytime service active.'
  desc 'The daytime service runs as root from the inetd daemon and can provide an opportunity for Denial of Service PING or PING-PONG attacks.   The daytime service is unnecessary and it increases the attack vector of the system.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out daytime service lines for both TCP and UDP protocols. 
Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29504'
  tag rid: 'SV-38708r1_rule'
  tag stig_id: 'GEN009200'
  tag gtitle: 'GEN009200'
  tag fix_id: 'F-33062r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
