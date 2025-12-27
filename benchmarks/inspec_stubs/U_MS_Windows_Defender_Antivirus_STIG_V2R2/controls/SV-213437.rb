control 'SV-213437' do
  title 'Windows Defender AV must be configured to not allow local override of monitoring for file and program activity.'
  desc 'This policy setting configures a local override for the configuration of monitoring for file and program activity on your computer. This setting can only be set by Group Policy. If you enable this setting the local preference setting will take priority over Group Policy. If you disable or do not configure this setting Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for monitoring file and program activity on your computer" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideDisableOnAccessProtection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for monitoring file and program activity on your computer" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14662r314620_chk'
  tag severity: 'medium'
  tag gid: 'V-213437'
  tag rid: 'SV-213437r569189_rule'
  tag stig_id: 'WNDF-AV-000013'
  tag gtitle: 'SRG-APP-000112'
  tag fix_id: 'F-14660r314621_fix'
  tag 'documentable'
  tag legacy: ['SV-89891', 'V-75211']
  tag cci: ['CCI-001695']
  tag nist: ['SC-18 (3)']
end
