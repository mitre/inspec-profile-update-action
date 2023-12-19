control 'SV-35010' do
  title 'The system must use initial TCP sequence numbers most resistant to sequence number guessing attacks.'
  desc 'One use of initial TCP sequence numbers is to verify bidirectional communication between two hosts, which provides some protection against spoofed source addresses being used by the connection originator. If the initial TCP sequence numbers for a host can be determined by an attacker, it may be possible to establish a TCP connection from a spoofed source address without bidirectional communication.'
  desc 'check', '# ndd -get /dev/tcp tcp_isn_passphrase

If the value 1 is not returned, this is a finding.'
  desc 'fix', '# ndd -set /dev/tcp tcp_isn_passphrase <a random passphrase>

Edit /etc/rc.config.d/nddconf and add/set:
TRANSPORT_NAME[x] = tcp
NDD_NAME[x] = tcp_isn_passphrase
NDD_VALUE[x] = <a random passphrase>'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36499r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12001'
  tag rid: 'SV-35010r1_rule'
  tag stig_id: 'GEN003580'
  tag gtitle: 'GEN003580'
  tag fix_id: 'F-31854r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
