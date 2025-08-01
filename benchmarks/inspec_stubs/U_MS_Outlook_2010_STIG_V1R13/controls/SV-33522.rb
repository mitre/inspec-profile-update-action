control 'SV-33522' do
  title "Trust EMail from senders in receiver's contact list must be enforced."
  desc "E-mail addresses in users' Contacts list are treated as safe senders for purposes of filtering junk e-mail. If this configuration is changed, e-mail from users' Contacts might be misclassified as junk and cause important information to be lost."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Trust E-mail from Contacts” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\mail

Criteria: If the value JunkMailTrustContacts is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Outlook Options -> Preferences -> Junk E-mail “Trust E-mail from Contacts” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34009r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17807'
  tag rid: 'SV-33522r1_rule'
  tag stig_id: 'DTOO223 - Outlook'
  tag gtitle: 'DTOO223 - Trust EMail from Contacts'
  tag fix_id: 'F-29697r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
