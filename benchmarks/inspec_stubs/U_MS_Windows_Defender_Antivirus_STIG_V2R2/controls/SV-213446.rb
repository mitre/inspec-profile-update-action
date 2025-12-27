control 'SV-213446' do
  title 'Windows Defender AV must be configured to enable behavior monitoring.'
  desc 'This policy setting allows you to configure behavior monitoring. If you enable or do not configure this setting behavior monitoring will be enabled. If you disable this setting behavior monitoring will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Turn on behavior monitoring" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableBehaviorMonitoring" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Turn on behavior monitoring" to "Enabled " or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14671r314647_chk'
  tag severity: 'medium'
  tag gid: 'V-213446'
  tag rid: 'SV-213446r569189_rule'
  tag stig_id: 'WNDF-AV-000022'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-14669r314648_fix'
  tag 'documentable'
  tag legacy: ['SV-89909', 'V-75229']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
