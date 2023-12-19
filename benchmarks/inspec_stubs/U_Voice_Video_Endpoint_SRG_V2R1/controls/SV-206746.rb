control 'SV-206746' do
  title 'The Voice Video Endpoint must register with a Voice Video Session Manager.'
  desc 'Authentication must not automatically give an entity access to an asset. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Registration authenticates and authorizes endpoints with the Voice Video Session Manager.

For most VoIP systems, registration is the process of centrally recording the user ID, endpoint MAC address, service/policy profile with 2 stage authentication prior to authorizing the establishment of the session and user service. The event of successful registration creates the session record immediately. VC systems register using a similar process with a gatekeeper. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Endpoint registers with a Voice Video Session Manager.

If the Voice Video Endpoint does not registers with a Voice Video Session Manager, this is a finding.'
  desc 'fix', 'Configure the Voice Video Endpoint to register with a Voice Video Session Manager.'
  impact 0.7
  ref 'DPMS Target Voice Video Endpoint'
  tag check_id: 'C-7002r363761_chk'
  tag severity: 'high'
  tag gid: 'V-206746'
  tag rid: 'SV-206746r604140_rule'
  tag stig_id: 'SRG-NET-000015-VVEP-00013'
  tag gtitle: 'SRG-NET-000015'
  tag fix_id: 'F-7002r363762_fix'
  tag 'documentable'
  tag legacy: ['SV-82475', 'V-67985']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
