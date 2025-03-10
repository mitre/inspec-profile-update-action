control 'SV-207205' do
  title 'The IPsec VPN Gateway must use IKEv2 for IPsec VPN security associations.'
  desc 'In order to prevent unauthorized connection of devices, unauthorized transfer of information, or unauthorized tunneling (i.e., embedding of data types within data types); organizations must disable or restrict unused or unnecessary physical and logical ports/protocols on information systems.

Use of IKEv2 leverages DoS protections because of improved bandwidth management and leverages more secure encryption algorithms.'
  desc 'check', 'Verify the IPsec VPN Gateway uses IKEv2 for IPsec VPN security associations.

If the IPsec VPN Gateway must use IKEv2 for IPsec VPN security associations, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use IKEv2 for IPsec VPN security associations.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7465r378236_chk'
  tag severity: 'medium'
  tag gid: 'V-207205'
  tag rid: 'SV-207205r608988_rule'
  tag stig_id: 'SRG-NET-000132-VPN-000460'
  tag gtitle: 'SRG-NET-000132'
  tag fix_id: 'F-7465r378237_fix'
  tag 'documentable'
  tag legacy: ['V-97081', 'SV-106219']
  tag cci: ['CCI-000382']
  tag nist: ['CM-7 b']
end
