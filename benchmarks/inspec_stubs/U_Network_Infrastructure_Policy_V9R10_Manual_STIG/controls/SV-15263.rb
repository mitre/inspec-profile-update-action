control 'SV-15263' do
  title 'All hosted NIPRNet-only applications must be located in a local enclave Demilitarized Zone (DMZ).'
  desc 'Without the protection of a DMZ, production networks will be prone to outside attacks as they are allowing externally accessible services to be accessed on the internal LAN.  This can cause many undesired consequences such as access to the entire network, Denial of Service attacks, or theft of sensitive information.'
  desc 'check', 'Review the network topology diagram and interview the ISSO to verify that all NIPRNet-only applications are located in a local enclave DMZ. 

If there are any NIPRNet-only applications not hosted in the enclave’s DMZ, this is a finding.'
  desc 'fix', 'Implement and move NIPRNet-only applications to a local enclave DMZ.'
  impact 0.5
  ref 'DPMS Target Network Infrastructure Policy'
  tag check_id: 'C-13708r10_chk'
  tag severity: 'medium'
  tag gid: 'V-14638'
  tag rid: 'SV-15263r4_rule'
  tag stig_id: 'NET0346'
  tag gtitle: 'An enclave DMZ architecture is not implemented.'
  tag fix_id: 'F-14743r6_fix'
  tag 'documentable'
  tag cci: ['CCI-002395']
  tag nist: ['SC-7 b']
end
