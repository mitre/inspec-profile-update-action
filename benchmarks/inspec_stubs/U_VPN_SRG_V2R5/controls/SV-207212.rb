control 'SV-207212' do
  title 'The IPsec VPN Gateway must use anti-replay mechanisms for security associations.'
  desc 'Anti-replay is an IPsec security mechanism at a packet level, which helps to avoid unwanted users from intercepting and modifying an ESP packet.'
  desc 'check', 'Verify the IPsec VPN Gateway  uses anti-replay mechanisms for security associations.

If the IPsec VPN Gateway does not use anti-replay mechanisms for security associations, this is a finding.'
  desc 'fix', 'Configure the IPsec VPN Gateway to use anti-replay mechanisms for security associations.'
  impact 0.5
  ref 'DPMS Target Virtual Private Network (VPN)'
  tag check_id: 'C-7472r378257_chk'
  tag severity: 'medium'
  tag gid: 'V-207212'
  tag rid: 'SV-207212r856700_rule'
  tag stig_id: 'SRG-NET-000147-VPN-000530'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-7472r378258_fix'
  tag 'documentable'
  tag legacy: ['V-97095', 'SV-106233']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
