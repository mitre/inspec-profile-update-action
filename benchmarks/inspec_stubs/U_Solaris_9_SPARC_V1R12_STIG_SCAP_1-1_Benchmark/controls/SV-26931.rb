control 'SV-26931' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'fix', 'Delete the DHCP client configuration.
# rm /etc/dhcp.*'
  impact 0.5
  ref 'DPMS Target Solaris 9 Sparc'
  tag severity: 'medium'
  tag gid: 'V-22548'
  tag rid: 'SV-26931r1_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'GEN007840'
  tag fix_id: 'F-24174r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
