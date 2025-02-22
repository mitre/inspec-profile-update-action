control 'SV-223405' do
  title 'Word attachments opened from Outlook must be in Protected View.'
  desc 'This policy setting allows you to determine if Word files in Outlook attachments open in Protected View.

If you enable this policy setting, Outlook attachments do not open in Protected View.

If you disable or do not configure this policy setting, Outlook attachments open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security>> Trust Center>> Protected View >> Turn off Protected View for attachments opened from Outlook is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\word\\security\\protectedview

If the value for disableattachmentsinpv is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set policy value for User Configuration >> Administrative Templates >> Microsoft Word 2016 >> Word Options >> Security>> Trust Center>> Protected View >> Turn off Protected View for attachments opened from Outlook to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25078r442434_chk'
  tag severity: 'medium'
  tag gid: 'V-223405'
  tag rid: 'SV-223405r879628_rule'
  tag stig_id: 'O365-WD-000006'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25066r442435_fix'
  tag 'documentable'
  tag legacy: ['SV-108991', 'V-99887']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
