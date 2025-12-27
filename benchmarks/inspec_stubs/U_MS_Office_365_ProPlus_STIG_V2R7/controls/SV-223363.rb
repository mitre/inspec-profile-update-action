control 'SV-223363' do
  title 'Level 2 file attachments must be blocked from being delivered.'
  desc 'This policy setting controls which types of attachments (determined by file extension) must be saved to disk before users can open them. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. 

If you enable this policy setting, you can specify a list of attachment file types to classify as Level 2, which forces users to actively decide to download the attachment to view it. 

If you disable or do not configure this policy setting, Outlook does not classify any file type extensions as Level 2. 

Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\\Security\\Security Form Settings" is configured to "Use Outlook Security Group Policy".'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Remove file extensions blocked as Level 2 is set to "Disabled".
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security\\FileExtensionsRemoveLevel2

If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Attachment Security >> Remove file extensions blocked as Level 2 to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25036r811494_chk'
  tag severity: 'medium'
  tag gid: 'V-223363'
  tag rid: 'SV-223363r811495_rule'
  tag stig_id: 'O365-OU-000018'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25024r442309_fix'
  tag 'documentable'
  tag legacy: ['SV-108905', 'V-99801']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
