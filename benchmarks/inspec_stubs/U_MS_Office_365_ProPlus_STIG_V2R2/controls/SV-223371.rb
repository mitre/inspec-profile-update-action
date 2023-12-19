control 'SV-223371' do
  title 'When an untrusted program attempts to send e-mail programmatically using the Outlook object model, Outlook must automatically deny it.'
  desc %q(This policy setting controls what happens when an untrusted program attempts to send e-mail programmatically using the Outlook object model. 

If you enable this policy setting, you can choose from four different options when an untrusted program attempts to send e-mail programmatically using the Outlook object model: 
- Prompt user - The user will be prompted to approve every access attempt.
- Automatically approve - Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended. 
- Automatically deny - Outlook will automatically deny programmatic access requests from any program. 
- Prompt user based on computer security. Outlook will only prompt users when antivirus software is out of date or not running. 

Important: This policy setting only applies if the "Outlook Security Mode" policy setting under "Microsoft Outlook 2016\Security\Security Form Settings" is configured to "Use Outlook Security Group Policy".

If you disable or do not configure this policy setting, when an untrusted application attempts to send mail programmatically, Outlook relies on the setting configured in the ''Programmatic Access'' section of the Trust Center.)
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when sending mail is set to "Enabled (Automatically Deny)".

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for promptoomsend is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when sending mail to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25044r442332_chk'
  tag severity: 'medium'
  tag gid: 'V-223371'
  tag rid: 'SV-223371r508019_rule'
  tag stig_id: 'O365-OU-000026'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-25032r442333_fix'
  tag 'documentable'
  tag legacy: ['SV-108921', 'V-99817']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
