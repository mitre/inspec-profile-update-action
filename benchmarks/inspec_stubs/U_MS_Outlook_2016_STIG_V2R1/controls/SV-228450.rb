control 'SV-228450' do
  title 'Object Model Prompt behavior for accessing User Property Formula must be configured.'
  desc "This policy setting controls what happens when a user designs a custom form in Outlook and attempts to bind an Address Information field to a combination or formula custom field. If you enable this policy setting, you can choose from four different options when an untrusted program attempts to access address information using the UserProperties. Find method of the Outlook object model: - Prompt user. The user will be prompted to approve every access attempt. - Automatically approve. Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended. - Automatically deny. Outlook will automatically deny programmatic access requests from any program. - Prompt user based on computer security. Outlook will only prompt users when antivirus software is out of date or not running. If you disable or do not configure this policy setting, when a user tries to bind an address information field to a combination or formula custom field in a custom form, Outlook relies on the setting configured in the 'Programmatic Access' section of the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt When accessing the Formula property of a UserProperty object" is set to "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value PromptOOMFormulaAccess is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt When accessing the Formula property of a UserProperty object" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30683r497672_chk'
  tag severity: 'medium'
  tag gid: 'V-228450'
  tag rid: 'SV-228450r508021_rule'
  tag stig_id: 'DTOO254'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30668r497838_fix'
  tag 'documentable'
  tag legacy: ['SV-85803', 'V-71179']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
