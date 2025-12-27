control 'SV-85655' do
  title 'Excel attachments opened from Outlook must be in Protected View.'
  desc 'This policy setting allows you to determine if Excel files in Outlook attachments open in Protected View. If you enable this policy setting, Outlook attachments do not open in Protected View. If you disable or do not configure this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Protected View "Turn off Protected View for attachments opened from Outlook" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\Excel\\security\\protectedview

Criteria: If the value DisableAttachmentsInPV  is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Protected View "Turn off Protected View for attachments opened from Outlook" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71459r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71031'
  tag rid: 'SV-85655r1_rule'
  tag stig_id: 'DTOO293'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77363r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
