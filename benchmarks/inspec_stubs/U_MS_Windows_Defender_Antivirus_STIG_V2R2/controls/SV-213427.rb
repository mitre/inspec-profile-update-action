control 'SV-213427' do
  title 'Windows Defender AV must be configured to automatically take action on all detected tasks.'
  desc 'This policy setting allows you to configure whether Windows Defender automatically takes action on all detected threats. The action to be taken on a particular threat is determined by the combination of the policy-defined action user-defined action and the signature-defined action. If you enable this policy setting Windows Defender does not automatically take action on the detected threats but prompts users to choose from the actions available for each threat. If you disable or do not configure this policy setting Windows Defender automatically takes action on all detected threats after a nonconfigurable delay of approximately five seconds.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> "Turn off routine remediation" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender

Criteria: If the value "DisableRoutinelyTakingAction" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> "Turn off routine remediation" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14652r314590_chk'
  tag severity: 'medium'
  tag gid: 'V-213427'
  tag rid: 'SV-213427r569189_rule'
  tag stig_id: 'WNDF-AV-000003'
  tag gtitle: 'SRG-APP-000279'
  tag fix_id: 'F-14650r314591_fix'
  tag 'documentable'
  tag legacy: ['SV-89831', 'V-75151']
  tag cci: ['CCI-001243']
  tag nist: ['SI-3 c 2']
end
