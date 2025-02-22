control 'SV-27416' do
  title 'The system must use initial TCP sequence numbers most resistant to sequence number guessing attacks.'
  desc 'One use of initial TCP sequence numbers is to verify bidirectional communication between two hosts, which provides some protection against spoofed source addresses being used by the connection originator.  If the initial TCP sequence numbers for a host can be determined by an attacker, it may be possible to establish a TCP connection from a spoofed source address without bidirectional communication.'
  desc 'fix', 'Edit /etc/default/inetinit and set the TCP_STRONG_ISS parameter to 2.'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-12001'
  tag rid: 'SV-27416r1_rule'
  tag stig_id: 'GEN003580'
  tag gtitle: 'GEN003580'
  tag fix_id: 'F-24688r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
