control 'SV-228476' do
  title 'Check e-mail addresses against addresses of certificates being used must be disallowed.'
  desc "This policy setting controls whether Outlook verifies the user's e-mail address with the address associated with the certificate used for signing. If you enable this policy setting, users can send messages signed with certificates that do not match their e-mail addresses. If you disable or do not configure this policy setting, Outlook verifies that the user's e-mail address matches the certificate being used for signing."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Do not check e-mail address against address of certificates being used" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value SupressNameChecks is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Do not check e-mail address against address of certificates being used" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30709r497750_chk'
  tag severity: 'medium'
  tag gid: 'V-228476'
  tag rid: 'SV-228476r508021_rule'
  tag stig_id: 'DTOO320'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30694r497751_fix'
  tag 'documentable'
  tag legacy: ['V-71277', 'SV-85901']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
