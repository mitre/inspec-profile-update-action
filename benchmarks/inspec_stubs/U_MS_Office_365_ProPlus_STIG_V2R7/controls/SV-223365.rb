control 'SV-223365' do
  title 'When a custom action is executed that uses the Outlook object model, Outlook must automatically deny it.'
  desc "This policy setting controls whether Outlook prompts users before executing a custom action. Custom actions add functionality to Outlook that can be triggered as part of a rule. Among other possible features, custom actions can be created that reply to messages in ways that circumvent the Outlook model's programmatic send protections. If you enable this policy setting, you can choose from four options to control how Outlook functions when a custom action is executed that uses the Outlook object model: 
- Prompt User
- Automatically Approve
- Automatically Deny 
- Prompt user based on computer security. This option enforces the default configuration in Outlook. 

If you disable or do not configure this policy setting, when Outlook or another program initiates a custom action using the Outlook object model, users are prompted to allow or reject the action. If this configuration is changed, malicious code can use the Outlook object model to compromise sensitive information or otherwise cause data and computing resources to be at risk. This is the equivalent of choosing Enabled -- Prompt user based on computer security."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Set Outlook object model custom actions execution prompt is set to "Enabled" and "Automatically Deny".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for promptoomcustomaction is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Set Outlook object model custom actions execution prompt to "Enabled" and select "Automatically Deny".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25038r442314_chk'
  tag severity: 'medium'
  tag gid: 'V-223365'
  tag rid: 'SV-223365r850637_rule'
  tag stig_id: 'O365-OU-000020'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-25026r442315_fix'
  tag 'documentable'
  tag legacy: ['SV-108909', 'V-99805']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
