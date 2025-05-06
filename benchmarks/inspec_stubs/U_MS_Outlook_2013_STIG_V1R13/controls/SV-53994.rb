control 'SV-53994' do
  title 'Custom Outlook Object Model (OOM) action execution prompts must be configured.'
  desc "Custom actions add functionality to Outlook that can be triggered as part of a rule. Among other possible features, custom actions can be created that reply to messages in ways that circumvent the Outlook model's programmatic send protections.
By default, when Outlook or another program initiates a custom action using the Outlook object model, users are prompted to allow or reject the action. If this configuration is changed, malicious code can use the Outlook object model to compromise sensitive information or otherwise cause data and computing resources to be at risk."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Custom Form Security "Set Outlook object model Custom Actions execution prompt" is "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value PromptOOMCustomAction is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Custom Form Security "Set Outlook object model Custom Actions execution prompt" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47965r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17802'
  tag rid: 'SV-53994r1_rule'
  tag stig_id: 'DTOO247'
  tag gtitle: 'DTOO247 - Custom OOM Action Exe. Prompt'
  tag fix_id: 'F-46883r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
