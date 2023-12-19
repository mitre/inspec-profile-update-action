control 'SV-235723' do
  title 'InPrivate mode must be disabled.'
  desc 'This setting specifies whether the user can open pages in InPrivate mode in Microsoft Edge.

If this policy is not configured or set it to "Enabled", users can open pages in InPrivate mode.

Set this policy to "Disabled" to stop users from using InPrivate mode.

Set this policy to "Forced" to always use InPrivate mode.

Policy options mapping:
- Enabled (0) = InPrivate mode available
- Disabled (1) = InPrivate mode disabled
- Forced (2) = InPrivate mode forced'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Configure InPrivate mode availability" must be set to "enabled" with the option value set to "InPrivate mode disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "InPrivateModeAvailability" is not set to "REG_DWORD = 1", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Configure InPrivate mode availability" to "enabled" and select "InPrivate mode disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38942r626365_chk'
  tag severity: 'medium'
  tag gid: 'V-235723'
  tag rid: 'SV-235723r626523_rule'
  tag stig_id: 'EDGE-00-000005'
  tag gtitle: 'SRG-APP-000080'
  tag fix_id: 'F-38905r626366_fix'
  tag 'documentable'
  tag cci: ['CCI-000166']
  tag nist: ['AU-10']
end
