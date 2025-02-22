control 'SV-33578' do
  title 'Action to demote an EMail Level 1 attachment to Level 2 must be configured.'
  desc 'Outlook uses two levels of security to restrict access to files attached to e-mail messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. If users can demote Level 1 files to Level 2, they will be able to access potentially dangerous files after saving them to disk, which could allow malicious code to affect their computers or compromise the security of sensitive information.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Attachment Security “Allow users to demote attachments to Level 2” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value AllowUsersToLowerAttachments is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Attachment Security “Allow users to demote attachments to Level 2” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34039r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17569'
  tag rid: 'SV-33578r1_rule'
  tag stig_id: 'DTOO241 - Outlook'
  tag gtitle: 'DTOO241 - Demote Attachments to Level 2'
  tag fix_id: 'F-29723r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
