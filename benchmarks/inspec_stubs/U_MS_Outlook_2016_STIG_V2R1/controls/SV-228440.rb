control 'SV-228440' do
  title 'The ability to display level 1 attachments must be disallowed.'
  desc "This policy setting controls whether Outlook blocks potentially dangerous attachments designated Level 1. Outlook uses two levels of security to restrict users' access to files attached to e-mail messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2.  If you enable this policy setting, Outlook users can gain access to Level 1 file type attachments by first saving the attachments to disk and then opening them, as with Level 2 attachments. If you disable this policy setting, Level 1 attachments do not display under any circumstances. If you do not configure this policy setting, Outlook completely blocks access to Level 1 files, and requires users to save Level 2 files to disk before opening them."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Display Level 1 attachments" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value ShowLevel1Attach is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Display Level 1 attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30673r497642_chk'
  tag severity: 'medium'
  tag gid: 'V-228440'
  tag rid: 'SV-228440r508021_rule'
  tag stig_id: 'DTOO240'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-30658r497643_fix'
  tag 'documentable'
  tag legacy: ['SV-85783', 'V-71159']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
