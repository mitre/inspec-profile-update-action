control 'SV-223361' do
  title 'The display of Level 1 attachments must be disabled in Outlook.'
  desc "This policy setting controls whether Outlook blocks potentially dangerous attachments designated Level 1. Outlook uses two levels of security to restrict users' access to files attached to e-mail messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. 

If you enable this policy setting, Outlook users can gain access to Level 1 file type attachments by first saving the attachments to disk and then opening them, as with Level 2 attachments. If you disable this policy setting, Level 1 attachments do not display under any circumstances. If you do not configure this policy setting, Outlook completely blocks access to Level 1 files, and requires users to save Level 2 files to disk before opening them."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Display Level 1 attachments is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

If the value ShowLevel1Attach is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security "Display Level 1 attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25034r442302_chk'
  tag severity: 'medium'
  tag gid: 'V-223361'
  tag rid: 'SV-223361r508019_rule'
  tag stig_id: 'O365-OU-000016'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25022r442303_fix'
  tag 'documentable'
  tag legacy: ['SV-108901', 'V-99797']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
