control 'SV-53997' do
  title 'Object Model Prompt behavior for programmatic address books must be configured.'
  desc 'If an untrusted application accesses the address book, the application could gain access to sensitive data and potentially change that data. By default, when an untrusted application attempts to access the address book programmatically, Outlook relies on the setting configured in the "Programmatic Access" section of the Trust Center. This setting determines whether Outlook will warn users about programmatic access attempts.
* Only when antivirus software is out of date or not running (the default setting)
* Every time
* Not at all
If the "Not at all" option is selected, Outlook will silently grant programmatic access to any program that requests it, which could allow a malicious program to gain access to sensitive information.
Note--This described default functionality assumes that the "Outlook Security Mode" Group Policy setting to ensure that Outlook security settings are configured by Group Policy has not been followed. If Group Policy security settings are used for Outlook, the "Programmatic Access" section of the Trust Center is not used. In this situation, the default is to prompt users based on computer security, which is the equivalent of the "Only when antivirus software is out of date or not running" option in the Trust Center, and the user experience is not affected.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when accessing an address book" is set to "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value PromptOOMAddressBookAccess is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when accessing an address book" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47967r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17568'
  tag rid: 'SV-53997r1_rule'
  tag stig_id: 'DTOO250'
  tag gtitle: 'DTOO250 - Object Model Prompt for Address Book'
  tag fix_id: 'F-46886r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
