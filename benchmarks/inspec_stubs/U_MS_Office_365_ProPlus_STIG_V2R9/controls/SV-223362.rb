control 'SV-223362' do
  title 'Level 1 file attachments must be blocked from being delivered.'
  desc 'This policy setting controls whether Outlook users can demote attachments to Level 2 by using a registry key, which will allow them to save files to disk and open them from that location. Outlook uses two levels of security to restrict access to files attached to email messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. 

If you enable this policy setting, users can create a list of Level 1 file types to demote to Level 2 by adding the file types to the following registry key: HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level1Remove. 

If this policy setting is disabled or not configured, users cannot demote Level 1 attachments to Level 2, and the HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Outlook\\Security\\Level1Remove registry key has no effect.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Remove file extensions blocked as Level 1 is set to "Disabled".
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security\\FileExtensionsRemoveLevel1

If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Remove file extensions blocked as Level 1 to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25035r442305_chk'
  tag severity: 'medium'
  tag gid: 'V-223362'
  tag rid: 'SV-223362r879628_rule'
  tag stig_id: 'O365-OU-000017'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25023r442306_fix'
  tag 'documentable'
  tag legacy: ['SV-108903', 'V-99799']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
