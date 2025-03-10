control 'SV-228442' do
  title 'Level 2 file extensions must be blocked and not removed.'
  desc 'This policy setting controls which types of attachments (determined by file extension) must be saved to disk before users can open them.  Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. If you enable this policy setting, you can specify a list of attachment file types to classify as Level 2, which forces users to actively decide to download the attachment to view it. If you disable or do not configure this policy setting, Outlook does not classify any file type extensions as Level 2. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\\Security\\Security Form Settings" is configured to "Use Outlook Security Group Policy."'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Remove file extensions blocked as Level 2" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security\\FileExtensionsRemoveLevel2

Criteria: If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Remove file extensions blocked as Level 2" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30675r497648_chk'
  tag severity: 'medium'
  tag gid: 'V-228442'
  tag rid: 'SV-228442r508021_rule'
  tag stig_id: 'DTOO245'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-30660r497649_fix'
  tag 'documentable'
  tag legacy: ['V-71163', 'SV-85787']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
