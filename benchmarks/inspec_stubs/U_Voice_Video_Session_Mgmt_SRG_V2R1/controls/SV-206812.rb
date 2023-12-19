control 'SV-206812' do
  title 'The Voice Video Session Manager must disable (prevent) auto-registration of Voice Video endpoints.'
  desc 'Authentication must not automatically give an entity access to an asset. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Registration authenticates and authorizes endpoints with the Voice Video Session Manager.

For most VoIP systems, registration is the process of centrally recording the user ID, endpoint MAC address, service/policy profile with 2 stage authentication prior to authorizing the establishment of the session and user service. The event of successful registration creates the session record immediately. VC systems register using a similar process with a gatekeeper. Auto-registration is an automatic means of detecting and registering a Voice Video endpoint on the network with a session manager and then downloading its configuration to the instrument. Auto-registration allows unauthorized instruments to be added or moved without authorization, possibly allowing theft of services or other malicious attack. Configuring the firewall to deny registration (port 1719, etc.) is another layer of defense.'
  desc 'check', 'Verify the Voice Video Session Manager prevents auto-registration of Voice Video endpoints. During initial system installation and testing, or subsequent large redeployments and additions, it may be necessary to enable auto-registration for a short period. When auto-registration is used under these circumstances, it must be disabled within 5 days and before the system is placed into service.

If the Voice Video Session Manager does not disable auto-registration of Voice Video endpoints outside of these conditions, this is a finding.'
  desc 'fix', 'Configure the Voice Video Session Manager to disable auto-registration of Voice Video endpoints.'
  impact 0.7
  ref 'DPMS Target Voice Video Session Management'
  tag check_id: 'C-7067r364625_chk'
  tag severity: 'high'
  tag gid: 'V-206812'
  tag rid: 'SV-206812r508661_rule'
  tag stig_id: 'SRG-NET-000015-VVSM-00002'
  tag gtitle: 'SRG-NET-000015'
  tag fix_id: 'F-7067r364626_fix'
  tag 'documentable'
  tag legacy: ['SV-76543', 'V-62053']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
