control 'SV-235720' do
  title 'Bypassing Microsoft Defender SmartScreen prompts for sites must be disabled.'
  desc 'This policy setting allows a decision to be made on whether users can override the Microsoft Defender SmartScreen warnings about potentially malicious websites.

If this setting is enabled, users cannot ignore Microsoft Defender SmartScreen warnings, and are blocked from continuing to the site.

If this setting is disabled or not configured, users can ignore Microsoft Defender SmartScreen warnings and continue to the site.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Prevent bypassing Microsoft Defender SmartScreen prompts for sites" must be set to "enabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PreventSmartScreenPromptOverride" is not set to "enabled", this is a finding.

If this machine is on SIPRNet, this is Not Applicable.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/SmartScreen settings/Prevent bypassing Microsoft Defender SmartScreen prompts for sites" to "enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38939r626356_chk'
  tag severity: 'medium'
  tag gid: 'V-235720'
  tag rid: 'SV-235720r626523_rule'
  tag stig_id: 'EDGE-00-000002'
  tag gtitle: 'SRG-APP-000073'
  tag fix_id: 'F-38902r626357_fix'
  tag 'documentable'
  tag cci: ['CCI-000870']
  tag nist: ['MA-3 (2)']
end
