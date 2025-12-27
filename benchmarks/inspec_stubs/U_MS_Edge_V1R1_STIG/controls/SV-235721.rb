control 'SV-235721' do
  title 'Bypassing of Microsoft Defender SmartScreen warnings about downloads must be disabled.'
  desc 'This policy setting allows a decision to be made on whether users can override Microsoft Defender SmartScreen warnings about unverified downloads.

If this setting is enabled, users cannot ignore Microsoft Defender SmartScreen warnings, and are prevented from completing the unverified downloads.

If this policy is disabled or not configured, users can ignore Microsoft Defender SmartScreen warnings and complete unverified downloads.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PreventSmartScreenPromptOverrideForFiles" is not set to "enabled", this is a finding.

If this machine is on SIPRNet, this is Not Applicable.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Prevent bypassing of Microsoft Defender SmartScreen warnings about downloads" must to "enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38940r626359_chk'
  tag severity: 'medium'
  tag gid: 'V-235721'
  tag rid: 'SV-235721r626523_rule'
  tag stig_id: 'EDGE-00-000003'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-38903r626360_fix'
  tag 'documentable'
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end
