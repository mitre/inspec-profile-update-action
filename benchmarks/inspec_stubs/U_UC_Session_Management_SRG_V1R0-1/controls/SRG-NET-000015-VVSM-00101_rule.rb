control 'SRG-NET-000015-VVSM-00101_rule' do
  title 'The Unified Communications Session Manager must disable (prevent) auto-registration of Voice Video Endpoints.'
  desc 'Authentication must not automatically give an entity access to an asset. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Registration authenticates and authorizes endpoints with the Unified Communications Session Manager.

For most VoIP systems, registration is the process of centrally recording the user ID, endpoint MAC address, service/policy profile with 2 stage authentication prior to authorizing the establishment of the session and user service. The event of successful registration creates the session record immediately. VC systems register using a similar process with a gatekeeper. Auto-registration is an automatic means of detecting and registering a Voice Video Endpoint on the network with a session manager and then downloading its configuration to the instrument. Auto-registration allows unauthorized instruments to be added or moved without authorization, possibly allowing theft of services or other malicious attack. Configuring the firewall to deny registration (port 1719, etc.) is another layer of defense.'
  desc 'check', 'Verify the Unified Communications Session Manager prevents auto-registration of Voice Video Endpoints.

If the Unified Communications Session Manager does not disable auto-registration of Voice Video Endpoints outside of these conditions, this is a finding.'
  desc 'fix', 'Configure the Unified Communications Session Manager to disable auto-registration of Voice Video Endpoints.'
  impact 0.7
  tag check_id: 'C-SRG-NET-000015-VVSM-00101_chk'
  tag severity: 'high'
  tag gid: 'SRG-NET-000015-VVSM-00101'
  tag rid: 'SRG-NET-000015-VVSM-00101_rule'
  tag stig_id: 'SRG-NET-000015-VVSM-00101'
  tag gtitle: 'SRG-NET-000015-VVSM-00101'
  tag fix_id: 'F-SRG-NET-000015-VVSM-00101_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
