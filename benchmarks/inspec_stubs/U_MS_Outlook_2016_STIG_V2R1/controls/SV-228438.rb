control 'SV-228438' do
  title 'Users customizing attachment security settings must be prevented.'
  desc 'This policy setting prevents users from overriding the set of attachments blocked by Outlook. If you enable this policy setting users will be prevented from overriding the set of attachments blocked by Outlook.  Outlook also checks the "Level1Remove" registry key when this setting is specified. If you disable or do not configure this policy setting, users will be allowed to override the set of attachments blocked by Outlook.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Prevent users from customizing attachment security settings" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook

Criteria: If the value DisallowAttachmentCustomization is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security "Prevent users from customizing attachment security settings" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30671r497636_chk'
  tag severity: 'medium'
  tag gid: 'V-228438'
  tag rid: 'SV-228438r508021_rule'
  tag stig_id: 'DTOO238'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-30656r497637_fix'
  tag 'documentable'
  tag legacy: ['V-71155', 'SV-85779']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
