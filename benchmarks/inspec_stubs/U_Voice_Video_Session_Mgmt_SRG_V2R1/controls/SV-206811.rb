control 'SV-206811' do
  title 'The Voice Video Session Manager must enforce registration of only approved Voice Video endpoints prior to operation.'
  desc 'Authentication must not automatically give an entity access to an asset. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Registration authenticates and authorizes endpoints with the Voice Video Session Manager.

For most VoIP systems, registration is the process of centrally recording the user ID, endpoint MAC address, service/policy profile with 2 stage authentication prior to authorizing the establishment of the session and user service. The event of successful registration creates the session record immediately. VC systems register using a similar process with a gatekeeper. Without enforcing registration, an adversary could impersonate a legitimate device on the Voice Video network.'
  desc 'check', 'Verify the Voice Video Session Manager enforces registration of only approved Voice Video endpoints prior to the endpoints operating with the system.

If the Voice Video Session Manager permits registration of unapproved Voice Video endpoints prior to operation, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to enforce registration of only approved Voice Video endpoints prior to operating with the system.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7066r364622_chk'
  tag severity: 'high'
  tag gid: 'V-206811'
  tag rid: 'SV-206811r508661_rule'
  tag stig_id: 'SRG-NET-000015-VVSM-00001'
  tag gtitle: 'SRG-NET-000015'
  tag fix_id: 'F-7066r364623_fix'
  tag 'documentable'
  tag legacy: ['SV-76541', 'V-62051']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
