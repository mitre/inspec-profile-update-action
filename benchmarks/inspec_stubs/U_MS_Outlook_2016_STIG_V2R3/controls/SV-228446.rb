control 'SV-228446' do
  title 'Object Model Prompt behavior for programmatic address books must be configured.'
  desc "This policy setting controls what happens when an untrusted program attempts to gain access to an Address Book using the Outlook object model. If you enable this policy setting, you can choose from four different options when an untrusted program attempts to programmatically access an Address Book using the Outlook object model:- Prompt user - Users are prompted to approve every access attempt. - Automatically approve - Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended. - Automatically deny - Outlook will automatically deny programmatic access requests from any program.- Prompt user based on computer security - Outlook will rely on the setting in the 'Programmatic Access' section of the Trust Center. This is the default behavior. If you disable or do not configure this policy setting, when an untrusted application attempts to access the address book programmatically, Outlook relies on the setting configured in the 'Programmatic Access' section of the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when accessing an address book" is set to "Enabled (Automatically Deny)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value PromptOOMAddressBookAccess is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Security Form Settings -> Programmatic Security "Configure Outlook object model prompt when accessing an address book" to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30679r497660_chk'
  tag severity: 'medium'
  tag gid: 'V-228446'
  tag rid: 'SV-228446r508021_rule'
  tag stig_id: 'DTOO250'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-30664r497830_fix'
  tag 'documentable'
  tag legacy: ['SV-85795', 'V-71171']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
