control 'SV-223343' do
  title 'File attachments from Outlook must be opened in Excel in Protected mode.'
  desc 'This policy setting allows you to determine if Excel files in Outlook attachments open in Protected View.

If you enable this policy setting, Outlook attachments do not open in Protected View.

If you disable or do not configure this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Turn off Protected View for attachments opened from Outlook is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\excel\\security\\protectedview

If the value DisableAttachmentsInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Protected View >> Turn off Protected View for attachments opened from Outlook to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25016r442248_chk'
  tag severity: 'medium'
  tag gid: 'V-223343'
  tag rid: 'SV-223343r508019_rule'
  tag stig_id: 'O365-EX-000034'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25004r442249_fix'
  tag 'documentable'
  tag legacy: ['SV-108865', 'V-99761']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
