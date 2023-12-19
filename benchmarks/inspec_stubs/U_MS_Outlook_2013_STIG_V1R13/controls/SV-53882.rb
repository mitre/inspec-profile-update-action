control 'SV-53882' do
  title 'Trust EMail from senders in receivers contact list must be enforced.'
  desc "Email addresses in users' Contacts list are treated as safe senders for purposes of filtering junk email. If this configuration is changed, email from users' Contacts might be misclassified as junk and cause important information to be lost."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Junk E-mail "Trust E-mail from Contacts" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\mail

Criteria: If the value JunkMailTrustContacts is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Junk E-mail "Trust E-mail from Contacts" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47916r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17807'
  tag rid: 'SV-53882r1_rule'
  tag stig_id: 'DTOO223'
  tag gtitle: 'DTOO223 - Trust EMail from Contacts'
  tag fix_id: 'F-46788r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
