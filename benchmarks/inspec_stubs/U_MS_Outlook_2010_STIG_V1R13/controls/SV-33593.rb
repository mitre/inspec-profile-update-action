control 'SV-33593' do
  title 'Object Model Prompt behavior for programmatic access of user address data must be configured.'
  desc 'If an untrusted application accesses the recipient fields, the application could gain access to sensitive data and potentially change that data. This could result in mail being sent to the wrong party.  By default, when an untrusted application attempts to access recipient fields, Outlook relies on the setting configured in the "Programmatic Access" section of the Trust Center. This setting determines whether Outlook will warn users about programmatic access attempts: 
•	Only when antivirus software is out of date or not running (the default setting)
•	Every time
•	Not at all
If the "Not at all" option is selected, Outlook will silently grant programmatic access to any program that requests it, which could allow a malicious program to gain access to sensitive information.
Note   This described default functionality assumes that you have not followed the recommendation to enable the "Outlook Security Mode" Group Policy setting to ensure that Outlook security settings are configured by Group Policy. If Group Policy security settings are used for Outlook, the "Programmatic Access" section of the Trust Center is not used. In this situation, the default is to prompt users based on computer security, which is the equivalent of the "Only when antivirus software is out of date or not running" option in the Trust Center, and the user experience is not affected.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security “Configure Outlook object model prompt when reading address information” must be set to “Enabled (Automatically Deny)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value PromptOOMAddressInformationAccess is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Security Form Settings -> Programmatic Security “Configure Outlook object model prompt when reading address information” to “Enabled (Automatically Deny)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34055r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17572'
  tag rid: 'SV-33593r1_rule'
  tag stig_id: 'DTOO251 - Outlook'
  tag gtitle: 'DTOO251 - Object Model Prompt for Reading Address'
  tag fix_id: 'F-29735r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-002460']
  tag nist: ['SC-18 (4)']
end
