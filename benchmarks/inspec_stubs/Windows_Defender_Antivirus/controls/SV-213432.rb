control 'SV-213432' do
  title 'Windows Defender AV must be configured to disable local setting override for reporting to Microsoft MAPS.'
  desc 'This policy setting configures a local override for the configuration to join Microsoft MAPS. This setting can only be set by Group Policy. If you enable this setting the local preference setting will take priority over Group Policy. If you disable or do not configure this setting Group Policy will take priority over the local preference setting.'
  desc 'check', 'This is applicable to unclassified systems, for other systems this is NA.

Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Configure local setting override for reporting to Microsoft MAPS" is set to "Disabled" or "Not Configured".
     
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Spynet

Criteria: If the value "LocalSettingOverrideSpynetReporting" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'This is applicable to unclassified systems, for other systems this is NA.

Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> MAPS -> "Configure local setting override for reporting to Microsoft MAPS" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14657r314605_chk'
  tag severity: 'medium'
  tag gid: 'V-213432'
  tag rid: 'SV-213432r569189_rule'
  tag stig_id: 'WNDF-AV-000008'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14655r314606_fix'
  tag 'documentable'
  tag legacy: ['SV-89841', 'V-75161']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
