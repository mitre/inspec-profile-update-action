control 'SV-53837' do
  title 'Excel attachments opened from Outlook must be in Protected View.'
  desc 'This policy setting allows for determining whether Excel files in Outlook attachments open in Protected View. If enabling this policy setting, Outlook attachments do not open in Protected View. If disabling or not configuring this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> Protected View Turn off Protected View for attachments opened from Outlook" must be set to Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\Excel\\security\\protectedview

Criteria: If the value DisableAttachmentsInPV  is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> Protected View "Turn off Protected View for attachments opened from Outlook" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47893r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26617'
  tag rid: 'SV-53837r1_rule'
  tag stig_id: 'DTOO293'
  tag gtitle: 'DTOO293 - Turn off Protected View for attachments'
  tag fix_id: 'F-46740r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
