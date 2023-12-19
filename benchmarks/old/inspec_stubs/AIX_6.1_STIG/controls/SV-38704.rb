control 'SV-38704' do
  title 'The system must not have the chargen service active.'
  desc "When contacted, chargen responds with some random characters. When contacted via UDP, it 
will respond with a single UDP packet. When contacted via TCP, it will continue spewing characters until the client closes the connection. An easy attack is 'ping-pong' in which an attacker spoofs a packet between two machines running chargen. This will cause them to spew characters at each other, slowing the machines down and saturating the network.  
The chargen service is unnecessary and provides an opportunity for Denial of Service attack."
  desc 'check', 'Check the /etc/inetd.conf file for active TCP and UDP chargen service entries.

# grep chargen /etc/inetd.conf |grep -v \\#

If the chargen service is enabled, this is a finding.'
  desc 'fix', 'Edit /etc/inetd.conf and comment out the chargen service line for both udp and tcp protocols.

Restart the inetd service.   
#refresh -s inetd'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37800r1_chk'
  tag severity: 'medium'
  tag gid: 'V-29500'
  tag rid: 'SV-38704r1_rule'
  tag stig_id: 'GEN009140'
  tag gtitle: 'GEN009140'
  tag fix_id: 'F-33058r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
