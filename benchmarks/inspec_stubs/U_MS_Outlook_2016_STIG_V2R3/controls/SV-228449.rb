control 'SV-228449' do
  title 'Object Model Prompt behavior for the SaveAs method must be configured.'
  desc "This policy setting controls what happens when an untrusted program attempts to use the Save As command to programmatically save an item. If you enable this policy setting, you can choose from four different options when an untrusted program attempts to use the Save As command to programmatically save an item:- Prompt user. The user will be prompted to approve every access attempt. - Automatically approve. Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended. - Automatically deny. Outlook will automatically deny programmatic access requests from any program.- Prompt user based on computer security. Outlook will only prompt users when antivirus software is out of date or not running. This is the default configuration. If you disable or do not configure this policy setting, when an untrusted application attempts to use the Save As command, Outlook relies on the setting configured in the 'Programmatic Access' section of the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when executing Save As" is set to "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value PromptOOMSaveAs is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when executing Save As" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30682r497669_chk'
  tag severity: 'medium'
  tag gid: 'V-228449'
  tag rid: 'SV-228449r508021_rule'
  tag stig_id: 'DTOO253'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30667r497836_fix'
  tag 'documentable'
  tag legacy: ['SV-85801', 'V-71177']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
