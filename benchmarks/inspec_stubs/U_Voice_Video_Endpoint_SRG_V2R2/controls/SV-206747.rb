control 'SV-206747' do
  title 'The Voice Video Endpoint must dynamically implement configuration file changes.'
  desc 'Configuration management includes the management of security features and assurances through control of changes made to device hardware, software, and firmware throughout the life cycle of a product. Secure configuration management relies on performance and functional attributes of products to determine the appropriate security features and assurances used to measure a system configuration state. When configuration changes are made, it is critical for those changes to be implemented by the Voice Video Endpoint as quickly as possible. This ensures that Voice Video Endpoints communicate using the correct address books, session managers, gateways, and border elements.'
  desc 'check', 'Verify the Voice Video Endpoint dynamically implements configuration file changes. 

If the Voice Video Endpoint does not dynamically implement configuration file changes, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to dynamically implement configuration file changes.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7003r363764_chk'
  tag severity: 'high'
  tag gid: 'V-206747'
  tag rid: 'SV-206747r604140_rule'
  tag stig_id: 'SRG-NET-000015-VVEP-00019'
  tag gtitle: 'SRG-NET-000015'
  tag fix_id: 'F-7003r363765_fix'
  tag 'documentable'
  tag legacy: ['V-66717', 'SV-81207']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
