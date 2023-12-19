control 'SV-204783' do
  title 'The application server must provide the capability to immediately disconnect or disable remote access to the management interface.'
  desc 'Without the ability to immediately disconnect or disable remote access, an attack or other compromise taking progress would not be immediately stopped.

The application server must have the capability to immediately disconnect current users remotely accessing the management interface and/or disable further remote access. The speed of disconnect or disablement varies based on the criticality of missions/business functions and the need to eliminate immediate or future remote access to organizational information systems.'
  desc 'check', 'Review the application server product documentation and server configuration to ensure that there is a capability to immediately disconnect or disable remote access to the management interface.

If there is no capability, this is a finding.'
  desc 'fix', 'Configure the application server to have the capability to immediately disconnect or disable remote access to the management interface.'
  impact 0.5
  ref 'DPMS Target Application Server'
  tag check_id: 'C-4903r282996_chk'
  tag severity: 'medium'
  tag gid: 'V-204783'
  tag rid: 'SV-204783r508029_rule'
  tag stig_id: 'SRG-APP-000316-AS-000199'
  tag gtitle: 'SRG-APP-000316'
  tag fix_id: 'F-4903r282997_fix'
  tag 'documentable'
  tag legacy: ['V-57415', 'SV-71687']
  tag cci: ['CCI-002322']
  tag nist: ['AC-17 (9)']
end
