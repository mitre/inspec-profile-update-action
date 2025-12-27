control 'SV-223351' do
  title 'Junk email level must be enabled at a setting of High.'
  desc "This policy setting controls your Junk E-mail protection level. The Junk E-mail Filter in Outlook helps to prevent junk e-mail messages, also known as spam, from cluttering user's Inbox. The filter evaluates each incoming message based on several factors, including the time when the message was sent and the content of the message. The filter does not single out any particular sender or message type, but instead analyzes each message based on its content and structure to discover whether or not it is probably spam.

If you enable this policy setting, you can select one of the four listed options available. After you select an option, users will not be able to change it.

If you disable this policy setting, Outlook reverts to the user-defined protection level.

If you do not configure this policy setting, users can change their junk e-mail filtering options."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Preferences >> Junk E-mail >> Junk E-mail protection level is set to "High".
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\options\\mail

If the value junkmailprotection is set to "3", this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Outlook Options >> Preferences >> Junk E-mail >> Junk E-mail protection level to "Enabled" and set it to "High".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25024r822344_chk'
  tag severity: 'medium'
  tag gid: 'V-223351'
  tag rid: 'SV-223351r822346_rule'
  tag stig_id: 'O365-OU-000006'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-25012r822345_fix'
  tag 'documentable'
  tag legacy: ['SV-108881', 'V-99777']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
