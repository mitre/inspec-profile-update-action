control 'SV-33508' do
  title 'Outlook must be enforced as the default email, calendar, and contacts program.'
  desc 'Outlook is made the default program for E-mail, contacts, and calendar services when it is installed, although users can designate other programs as the default programs for these services. If another application is used to provide these services and your organization does not ensure the security of that application, it could be exploited to gain access to sensitive information or launch other malicious attacks.
If your organization has policies that govern the use of personal information management software, allowing users to change the default configuration could enable them to violate such policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other “Make Outlook the default program for E-mail, Contacts, and Calendar” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\general

Criteria: If the value Check Default Client is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Other “Make Outlook the default program for E-mail, Contacts, and Calendar” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33994r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17753'
  tag rid: 'SV-33508r1_rule'
  tag stig_id: 'DTOO229 - Outlook'
  tag gtitle: 'DTOO229 - Make Outlook the default program'
  tag fix_id: 'F-29683r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
