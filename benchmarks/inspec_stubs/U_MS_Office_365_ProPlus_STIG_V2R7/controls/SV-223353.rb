control 'SV-223353' do
  title 'Outlook must be configured to prevent users overriding attachment security settings.'
  desc 'This policy setting prevents users from overriding the set of attachments blocked by Outlook.

If you enable this policy setting users will be prevented from overriding the set of attachments blocked by Outlook. Outlook also checks the "Level1Remove" registry key when this setting is specified. 

If you disable or do not configure this policy setting, users will be allowed to override the set of attachments blocked by Outlook.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Prevent users from customizing attachment security settings is set to "Enabled".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook

If the value for disallowattachmentcustomization is set to REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Prevent users from customizing attachment security settings to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25026r442278_chk'
  tag severity: 'medium'
  tag gid: 'V-223353'
  tag rid: 'SV-223353r850635_rule'
  tag stig_id: 'O365-OU-000008'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-25014r442279_fix'
  tag 'documentable'
  tag legacy: ['SV-108885', 'V-99781']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
