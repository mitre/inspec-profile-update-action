control 'SV-227792' do
  title 'The system must use initial TCP sequence numbers most resistant to sequence number guessing attacks.'
  desc 'One use of initial TCP sequence numbers is to verify bidirectional communication between two hosts, which provides some protection against spoofed source addresses being used by the connection originator.  If the initial TCP sequence numbers for a host can be determined by an attacker, it may be possible to establish a TCP connection from a spoofed source address without bidirectional communication.'
  desc 'check', '# grep "TCP_STRONG_ISS=2" /etc/default/inetinit
If this variable is not set, this is a finding.'
  desc 'fix', 'Edit /etc/default/inetinit and set the TCP_STRONG_ISS parameter to 2.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-29954r489730_chk'
  tag severity: 'medium'
  tag gid: 'V-227792'
  tag rid: 'SV-227792r603266_rule'
  tag stig_id: 'GEN003580'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29942r489731_fix'
  tag 'documentable'
  tag legacy: ['SV-27416', 'V-12001']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
