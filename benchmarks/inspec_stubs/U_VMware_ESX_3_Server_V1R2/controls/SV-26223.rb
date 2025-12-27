control 'SV-26223' do
  title 'The DHCP client must be disabled if not needed.'
  desc 'DHCP allows for the unauthenticated configuration of network parameters on the system by exchanging information with a DHCP server.'
  desc 'check', 'If the DHCP client is needed by the system, this is not applicable.
Determine if the DHCP client is disabled.  If it is not, this is a finding.'
  desc 'fix', "Disable the system's DHCP client."
  impact 0.5
  ref 'DPMS Target ESX Server 3'
  tag check_id: 'C-29304r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22548'
  tag rid: 'SV-26223r1_rule'
  tag stig_id: 'GEN007840'
  tag gtitle: 'GEN007840'
  tag fix_id: 'F-26336r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
