control 'SV-95685' do
  title 'The extension mobility feature must be globally disabled.'
  desc 'Extension mobility is a feature of a VVoIP system that permits a person to transfer their phone number extension and phone features (or configuration) to a phone that is not in their normal workspace. This is useful when a person is visiting a remote office away from their normal office and typically functions within an established enterprise wide VVoIP system where the system is designed as a contiguous system. In this case, the system is typically a single vendor solution. The system might be within one LAN/CAN may include multiple LAN/CANs at multiple interconnected sites. To activate this feature, the user approaches a phone that is not their regular phone and identifies themselves to the phone system via a username, password, pin, code, or some combination of these. Upon validation, the system configuration manager will configure the temporary phone to match the configuration of the user’s regular phone. Minimally, the phone number is transferred and possibly some or all of the user’s speed dial numbers and other personal preferences. This capability is dependant upon the capabilities of the temporary phone. Once activated the user’s inbound calls are directed to the temporary location. The user’s regular phone may or may not maintain its normal capabilities and also may also answer inbound calls.

Extension mobility is similar to but not the same as forwarding ones calls. Forwarding is typically activated from the user’s normal phone or their user preferences configuration settings. Forwarding is therefore pre-set to a known location. Extension mobility is typically activated from the remote location and is activated upon arrival at that location. Extension mobility should be available only to those individuals that need to use the feature.'
  desc 'check', 'If the extension mobility feature of the VVoIP system can be configured per user and is enabled, this is not applicable.

Interview the ISSO to validate compliance with the following requirement:

Verify the configuration for the extension mobility feature is globally disabled.

If the extension mobility feature is not globally disabled, this is a finding.'
  desc 'fix', 'Configure the extension mobility feature to be globally disabled on the VVoIP system.'
  impact 0.5
  ref 'DPMS Target VVoiP Device'
  tag check_id: 'C-25775r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80973'
  tag rid: 'SV-95685r2_rule'
  tag stig_id: 'VVoIP 1675'
  tag gtitle: 'VVoIP 1675'
  tag fix_id: 'F-87831r1_fix'
  tag 'documentable'
end
