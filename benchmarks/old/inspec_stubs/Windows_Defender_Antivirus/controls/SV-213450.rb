control 'SV-213450' do
  title 'Windows Defender AV must be configured to perform a weekly scheduled scan.'
  desc 'This policy setting allows you to specify the day of the week on which to perform a scheduled scan. The scan can also be configured to run every day or to never run at all. This setting can be configured with the following ordinal number values: (0x0) Every Day  (0x1) Sunday  (0x2) Monday  (0x3) Tuesday  (0x4) Wednesday  (0x5) Thursday  (0x6) Friday  (0x7) Saturday  (0x8) Never (default)  If you enable this setting a scheduled scan will run at the frequency specified. If you disable or do not configure this setting a scheduled scan will run at a default frequency.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Specify the day of the week to run a scheduled scan" is set to "Enabled" and anything other than "Never" selected in the drop down box.
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Scan

Criteria: If the value "ScheduleDay" is REG_DWORD = 0x8, this is a finding.

Values of 0x0 through 0x7 are acceptable and not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Scan -> "Specify the day of the week to run a scheduled scan" to "Enabled " and select anything other than "Never" in the drop down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14675r314659_chk'
  tag severity: 'medium'
  tag gid: 'V-213450'
  tag rid: 'SV-213450r569189_rule'
  tag stig_id: 'WNDF-AV-000026'
  tag gtitle: 'SRG-APP-000277'
  tag fix_id: 'F-14673r314660_fix'
  tag 'documentable'
  tag legacy: ['SV-89917', 'V-75237']
  tag cci: ['CCI-001241']
  tag nist: ['SI-3 c 1']
end
