control 'SV-213441' do
  title 'Windows Defender AV Group Policy settings must take priority over the local preference settings.'
  desc 'This policy setting configures a local override for the configuration to turn on real-time protection. This setting can only be set by Group Policy. If you enable this setting the local preference setting will take priority over Group Policy. If you disable or do not configure this setting Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override to turn on real-time protection" is set to "Disabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideDisableRealtimeMonitoring" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override to turn on real-time protection" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14666r314632_chk'
  tag severity: 'medium'
  tag gid: 'V-213441'
  tag rid: 'SV-213441r569189_rule'
  tag stig_id: 'WNDF-AV-000017'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14664r314633_fix'
  tag 'documentable'
  tag legacy: ['SV-89899', 'V-75219']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
