control 'SV-213443' do
  title 'Windows Defender AV must be configured to monitor for file and program activity.'
  desc 'This policy setting allows you to configure monitoring for file and program activity. If you enable or do not configure this setting monitoring for file and program activity will be enabled. If you disable this setting monitoring for file and program activity will be disabled.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Monitor file and program activity on your computer to be scanned" is set to "Enabled" or "Not Configured".
 
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection

Criteria: If the value "DisableOnAccessProtection" is REG_DWORD = 0, this is not a finding.

If the value does not exist, this is not a finding.

If the value is 1, this is a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Real-time Protection -> "Monitor file and program activity on your computer" to "Enabled" or "Not Configured".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14668r314638_chk'
  tag severity: 'medium'
  tag gid: 'V-213443'
  tag rid: 'SV-213443r569189_rule'
  tag stig_id: 'WNDF-AV-000019'
  tag gtitle: 'SRG-APP-000278'
  tag fix_id: 'F-14666r314639_fix'
  tag 'documentable'
  tag legacy: ['SV-89903', 'V-75223']
  tag cci: ['CCI-001242']
  tag nist: ['SI-3 c 1']
end
