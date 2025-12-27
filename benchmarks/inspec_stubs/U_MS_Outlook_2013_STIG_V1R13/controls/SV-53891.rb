control 'SV-53891' do
  title 'Outlook must be enforced as the default email, calendar, and contacts program.'
  desc 'Outlook is made the default program for email, contacts, and calendar services when it is installed, although users can designate other programs as the default programs for these services. If another application is used to provide these services and the organization does not ensure the security of that application, it could be exploited to gain access to sensitive information or launch other malicious attacks.
When an organization has policies that govern the use of personal information management software, allowing users to change the default configuration could enable them to violate such policies.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other "Make Outlook the default program for E-mail, Contacts, and Calendar" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\general

Criteria: If the value Check Default Client is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Other "Make Outlook the default program for E-mail, Contacts, and Calendar" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47920r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17753'
  tag rid: 'SV-53891r1_rule'
  tag stig_id: 'DTOO229'
  tag gtitle: 'DTOO229 - Make Outlook the default program'
  tag fix_id: 'F-46798r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
