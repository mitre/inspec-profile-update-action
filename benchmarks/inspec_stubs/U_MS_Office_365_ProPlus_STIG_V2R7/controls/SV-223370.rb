control 'SV-223370' do
  title 'When an untrusted program attempts to programmatically send e-mail in Outlook using the Response method of a task or meeting request, Outlook must automatically deny it.'
  desc "This policy setting controls what happens when an untrusted program attempts to programmatically send e-mail in Outlook using the Response method of a task or meeting request. 

If you enable this policy setting, you can choose from four different options when an untrusted program attempts to programmatically send e-mail using the Response method of a task or meeting request:
- Prompt user. The user will be prompted to approve every access attempt.
- Automatically approve. Outlook will automatically grant programmatic access requests from any program. This option can create a significant vulnerability, and is not recommended.
- Automatically deny. Outlook will automatically deny programmatic access requests from any program. 
- Prompt user based on computer security. Outlook only prompts users when antivirus software is out of date or not running. This is the default configuration. 

If you disable or do not configure this policy setting, when an untrusted application attempts to respond to tasks or meeting requests programmatically, Outlook relies on the setting configured in the ''Programmatic Access'' section of the Trust Center."
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when responding to meeting and task requests is set to "Enabled (Automatically Deny)"

Use the Windows Registry to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\outlook\\security

If the value for promptoommeetingtaskrequestresponse is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Security >> Security Form Settings >> Programmatic Security >> Configure Outlook object model prompt when responding to meeting and task requests to "Enabled (Automatically Deny)".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25043r442329_chk'
  tag severity: 'medium'
  tag gid: 'V-223370'
  tag rid: 'SV-223370r863218_rule'
  tag stig_id: 'O365-OU-000025'
  tag gtitle: 'SRG-APP-000488'
  tag fix_id: 'F-25031r863218_fix'
  tag 'documentable'
  tag legacy: ['SV-108919', 'V-99815']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
