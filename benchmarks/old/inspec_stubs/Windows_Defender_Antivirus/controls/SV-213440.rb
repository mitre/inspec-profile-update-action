control 'SV-213440' do
  title 'Windows Defender AV must be configured to not allow override of behavior monitoring.'
  desc 'This policy setting configures a local override for the configuration of behavior monitoring. This setting can only be set by Group Policy. If you enable this setting the local preference setting will take priority over Group Policy. If you disable or do not configure this setting Group Policy will take priority over the local preference setting.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for turn on behavior monitoring" is set to "Disabled" or "Not Configure".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "LocalSettingOverrideDisableBehaviorMonitoring" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Configure local setting override for turn on behavior monitoring" to "Disabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14665r314629_chk'
  tag severity: 'medium'
  tag gid: 'V-213440'
  tag rid: 'SV-213440r569189_rule'
  tag stig_id: 'WNDF-AV-000016'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14663r314630_fix'
  tag 'documentable'
  tag legacy: ['SV-89897', 'V-75217']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
