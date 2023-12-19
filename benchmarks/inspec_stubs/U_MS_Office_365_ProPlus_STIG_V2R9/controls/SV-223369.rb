control 'SV-223369' do
  title 'When an untrusted program attempts to gain access to a recipient field, such as the, To: field, using the Outlook object model, Outlook must automatically deny it.'
  desc "This policy setting controls what happens when an untrusted program attempts to gain access to a recipient field, such as the ''To:'' field, using the Outlook object model.

If you enable this policy setting, you can choose from four different options when an untrusted program attempts to access a recipient field using the Outlook object model:
- Prompt user. The user will be prompted to approve every access attempt.
- Automatically approve. Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended.
- Automatically deny. Outlook will automatically deny programmatic access requests from any program.
- Prompt user based on computer security. Outlook will only prompt users when antivirus software is out of date or not running. This is the default configuration.

If you disable or do not configure this policy setting, when an untrusted application attempts to access recipient fields, Outlook relies on the setting configured in the ''Programmatic Access'' section of the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when reading address information is set to "Enabled (Automatically Deny)".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for promptoomaddressinformationaccess is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when reading address information to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25042r442326_chk'
  tag severity: 'medium'
  tag gid: 'V-223369'
  tag rid: 'SV-223369r879859_rule'
  tag stig_id: 'O365-OU-000024'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-25030r863217_fix'
  tag 'documentable'
  tag legacy: ['SV-108917', 'V-99813']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
