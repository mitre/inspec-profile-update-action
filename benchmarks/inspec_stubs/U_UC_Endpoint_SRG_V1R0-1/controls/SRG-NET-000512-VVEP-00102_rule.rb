control 'SRG-NET-000512-VVEP-00102_rule' do
  title 'The Unified Communications Endpoint must be configured to dynamically implement configuration file changes.'
  desc 'Configuration management includes the management of security features and assurances through control of changes made to device hardware, software, and firmware throughout the life cycle of a product. Secure configuration management relies on performance and functional attributes of products to determine the appropriate security features and assurances used to measure a system configuration state. When configuration changes are made, it is critical for those changes to be implemented by the Unified Communications Endpoint as quickly as possible. This ensures that Unified Communications Endpoints communicate using the correct address books, session managers, gateways, and border elements.'
  desc 'check', 'Verify the Unified Communications Endpoint dynamically implements configuration file changes. 

If the Unified Communications Endpoint does not dynamically implement configuration file changes, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Endpoint to dynamically implement configuration file changes.'
  impact 0.5
  tag check_id: 'C-SRG-NET-000512-VVEP-00102_chk'
  tag severity: 'medium'
  tag gid: 'SRG-NET-000512-VVEP-00102'
  tag rid: 'SRG-NET-000512-VVEP-00102_rule'
  tag stig_id: 'SRG-NET-000512-VVEP-00102'
  tag gtitle: 'SRG-NET-000512-VVEP-00102'
  tag fix_id: 'F-SRG-NET-000512-VVEP-00102_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
