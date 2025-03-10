control 'SV-33595' do
  title 'Object Model Prompt for programmatic email send behavior must be configured.'
  desc 'If an untrusted application programmatically sends e-mail, that application could send mail that includes malicious code, impersonate a user, or launch a denial-of-service attack by sending a large volume of mail to a user or group of users.  By default, when an untrusted application attempts to send mail programmatically, Outlook relies on the setting configured in the "Programmatic Access" section of the Trust Center. This setting determines whether Outlook will warn users about programmatic access attempts: 
•	Only when antivirus software is out of date or not running (the default setting)
•	Every time
•	Not at all
If the "Not at all" option is selected, Outlook will silently grant programmatic access to any program that requests it, which could allow a malicious program to gain access to sensitive information.
Note   This described default functionality assumes that you have not followed the recommendation to enable the "Outlook Security Mode" Group Policy setting to ensure that Outlook security settings are configured by Group Policy. If Group Policy security settings are used for Outlook, the "Programmatic Access" section of the Trust Center is not used. In this situation, the default is to prompt users based on computer security, which is the equivalent of the "Only when antivirus software is out of date or not running" option in the Trust Center, and the user experience is not affected.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security “Configure Outlook object model prompt when sending mail” must be set to “Enabled (Automatically Deny)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value PromptOOMSend is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security “Configure Outlook object model prompt when sending mail” to “Enabled (Automatically Deny)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34057r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17574'
  tag rid: 'SV-33595r1_rule'
  tag stig_id: 'DTOO249 - Outlook'
  tag gtitle: 'DTOO249 - Object Model Prmpt for auto email send'
  tag fix_id: 'F-29737r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
