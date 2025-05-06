control 'SV-223360' do
  title 'The ability to demote attachments from Level 2 to Level 1 must be disabled.'
  desc 'This policy setting controls whether Outlook users can demote attachments to Level 2 by using a registry key, which will allow them to save files to disk and open them from that location. Outlook uses two levels of security to restrict access to files attached to e-mail messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. 

If you enable this policy setting, users can create a list of Level 1 file types to demote to Level 2 by adding the file types to the following registry key: HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Outlook\\Security\\Level1Remove. 

If you disable or do not configure this policy setting, users cannot demote level 1 attachments to level 2, and the HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\14.0\\Outlook\\Security\\Level1Remove registry key has no effect.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Allow users to demote attachments to Level 2 is set to "Disabled".
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value allowuserstolowerattachments is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Allow users to demote attachments to Level 2 to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25033r442299_chk'
  tag severity: 'medium'
  tag gid: 'V-223360'
  tag rid: 'SV-223360r508019_rule'
  tag stig_id: 'O365-OU-000015'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25021r442300_fix'
  tag 'documentable'
  tag legacy: ['SV-108899', 'V-99795']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
