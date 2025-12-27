control 'SV-228441' do
  title 'Level 1 file extensions must be blocked and not removed.'
  desc %q(This policy setting controls which types of attachments (determined by file extension) Outlook prevents from being delivered. Outlook uses two levels of security to restrict users' access to files attached to e-mail messages or other items. Files with specific extensions can be categorized as Level 1 (users cannot view the file) or Level 2 (users can open the file after saving it to disk). Users can freely open files of types that are not categorized as Level 1 or Level 2. If you enable this policy setting, you can specify the removal of file type extensions as that Outlook classifies as Level 1--that is, to be blocked from delivery--by entering them in the text field provided separated by semicolons. If you disable or do not configure this policy setting, Outlook classifies a number of potentially harmful file types (such as those with .exe, .reg, and .vbs extensions) as Level 1 and blocks files with those extensions from being delivered. Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\Security\Security Form Settings" is configured to "Use Outlook Security Group Policy.")
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Remove file extensions blocked as Level 1" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security\\FileExtensionsRemoveLevel1

Criteria: If the registry key exists, this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Attachment Security "Remove file extensions blocked as Level 1" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30674r497645_chk'
  tag severity: 'medium'
  tag gid: 'V-228441'
  tag rid: 'SV-228441r508021_rule'
  tag stig_id: 'DTOO244'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-30659r497646_fix'
  tag 'documentable'
  tag legacy: ['SV-85785', 'V-71161']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
