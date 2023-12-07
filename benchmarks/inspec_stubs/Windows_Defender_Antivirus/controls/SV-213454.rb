control 'SV-213454' do
  title 'Windows Defender AV must be configured to check for definition updates daily.'
  desc 'This policy setting allows you to specify the day of the week on which to check for definition updates. The check can also be configured to run every day or to never run at all. This setting can be configured with the following ordinal number values: (0x0) Every Day (default)  (0x1) Sunday   (0x2) Monday  (0x3) Tuesday  (0x4) Wednesday  (0x5) Thursday  (0x6) Friday  (0x7) Saturday  (0x8) Never  If you enable this setting the check for definition updates will occur at the frequency specified. If you disable or do not configure this setting the check for definition updates will occur at a default frequency.'
  desc 'check', 'Verify the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Signature Updates -> "Specify the day of the week to check for definition updates" is set to "Enabled" and "Every Day" is selected in the drop down box.
  
Procedure: Use the Windows Registry Editor to navigate to the following key: 
HKLM\\Software\\Policies\\Microsoft\\Windows Defender\\Signature Updates

Criteria: If the value "ScheduleDay" is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Signature Updates -> "Specify the day of the week to check for definition updates" to "Enabled" and select "Every Day" in the drop down box.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Defender Antivirus'
  tag check_id: 'C-14679r793136_chk'
  tag severity: 'medium'
  tag gid: 'V-213454'
  tag rid: 'SV-213454r793137_rule'
  tag stig_id: 'WNDF-AV-000030'
  tag gtitle: 'SRG-APP-000261'
  tag fix_id: 'F-14677r314672_fix'
  tag 'documentable'
  tag legacy: ['SV-89925', 'V-75245']
  tag cci: ['CCI-001308']
  tag nist: ['SI-8 (2)']
end
