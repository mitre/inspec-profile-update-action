control 'SV-228444' do
  title 'Custom Outlook Object Model (OOM) action execution prompts must be configured.'
  desc "This policy setting controls whether Outlook prompts users before executing a custom action. Custom actions add functionality to Outlook that can be triggered as part of a rule. Among other possible features, custom actions can be created that reply to messages in ways that circumvent the Outlook model's programmatic send protections. If you enable this policy setting, you can choose from four options to control how Outlook functions when a custom action is executed that uses the Outlook object model: * Prompt User * Automatically Approve * Automatically Deny * Prompt user based on computer security. This option enforces the default configuration in Outlook. If you disable or do not configure this policy setting, when Outlook or another program initiates a custom action using the Outlook object model, users are prompted to allow or reject the action. If this configuration is changed, malicious code can use the Outlook object model to compromise sensitive information or otherwise cause data and computing resources to be at risk. This is the equivalent of choosing Enabled -- Prompt user based on computer security."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Custom Form Security "Set Outlook object model Custom Actions execution prompt" is set to "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value PromptOOMCustomAction is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Custom Form Security "Set Outlook object model Custom Actions execution prompt" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30677r497654_chk'
  tag severity: 'medium'
  tag gid: 'V-228444'
  tag rid: 'SV-228444r508021_rule'
  tag stig_id: 'DTOO247'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30662r497655_fix'
  tag 'documentable'
  tag legacy: ['V-71167', 'SV-85791']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
