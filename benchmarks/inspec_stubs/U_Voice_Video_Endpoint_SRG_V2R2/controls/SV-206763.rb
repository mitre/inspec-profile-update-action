control 'SV-206763' do
  title 'The Voice Video Endpoint must implement replay-resistant authentication mechanisms for network access.'
  desc 'A replay attack may enable an unauthorized user to gain access to the application. Authentication sessions between the authenticator and the application validating the user credentials must not be vulnerable to a replay attack. An authentication process resists replay attacks if it is impractical to achieve a successful authentication by recording and replaying a previous authentication message. Voice video endpoints often use passwords or PINs that can be easily exploited.

This requirement only applies to components where this is specific to the function of the device or has the concept of an organizational user. This does not apply to authentication for the purpose of configuring the device itself (i.e., device management).'
  desc 'check', 'Verify the Voice Video Endpoint implements replay-resistant authentication mechanisms for network access. 

If the Voice Video Endpoint does not implement replay-resistant authentication mechanisms for network access, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to implement replay-resistant authentication mechanisms for network access.'
  impact 0.5
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7019r363812_chk'
  tag severity: 'medium'
  tag gid: 'V-206763'
  tag rid: 'SV-206763r604140_rule'
  tag stig_id: 'SRG-NET-000147-VVEP-00015'
  tag gtitle: 'SRG-NET-000147'
  tag fix_id: 'F-7019r363813_fix'
  tag 'documentable'
  tag legacy: ['SV-81199', 'V-66709']
  tag cci: ['CCI-001942']
  tag nist: ['IA-2 (9)']
end
