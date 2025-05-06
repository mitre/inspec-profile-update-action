control 'SV-38711' do
  title 'The system must not have the echo service active.'
  desc 'The echo service can be used in Denial of Service or SMURF attacks.  It can also used at someone else to get through a firewall or start a data storm.  The echo service is unnecessary and it increases the attack vector of the system.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the echo service lines for both TCP and UDP. 

Restart the inetd service.   
# refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag severity: 'medium'
  tag gid: 'V-29507'
  tag rid: 'SV-38711r1_rule'
  tag stig_id: 'GEN009230'
  tag gtitle: 'GEN009230'
  tag fix_id: 'F-33065r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
