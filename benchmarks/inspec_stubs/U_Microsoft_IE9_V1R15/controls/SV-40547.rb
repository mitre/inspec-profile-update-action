control 'SV-40547' do
  title 'Security checking features must be enforced.'
  desc 'This policy setting turns off the Security Settings Check feature, which checks Internet Explorer security settings to determine when the settings put Internet Explorer at risk. If you enable this policy setting, the security settings check will not be performed. If you disable or do not configure this policy setting, the security settings check will be performed.'
  desc 'check', 'The policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off the Security Settings Check feature" must be “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key:
HKLM\\Software\\Policies\\Microsoft\\Internet Explorer\\Security 

Criteria: If the value DisableSecuritySettingsCheck is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Internet Explorer -> "Turn off the Security Settings Check feature" to “Disabled”.'
  impact 0.5
  ref 'DPMS Target IE Version 9'
  tag check_id: 'C-39314r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15494'
  tag rid: 'SV-40547r1_rule'
  tag stig_id: 'DTBI325'
  tag gtitle: 'DTBI325 - Security settings check feature'
  tag fix_id: 'F-34423r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag ia_controls: 'ECSC-1'
end
