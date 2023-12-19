control 'SV-54066' do
  title 'Check e-mail addresses against addresses of certificates being used must be disallowed.'
  desc "This policy setting controls whether Outlook verifies the user's email address with the address associated with the certificate used for signing."
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Do not check e-mail address against address of certificates being used" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value SupressNameChecks is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Do not check e-mail address against address of certificates being used" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-48006r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26702'
  tag rid: 'SV-54066r1_rule'
  tag stig_id: 'DTOO320'
  tag gtitle: 'DTOO320 - Check e-mail address against certificate'
  tag fix_id: 'F-46946r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
