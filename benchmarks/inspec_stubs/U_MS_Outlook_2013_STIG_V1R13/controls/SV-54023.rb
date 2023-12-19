control 'SV-54023' do
  title 'Send all signed messages as clear signed messages must be configured.'
  desc %q(When users sign email messages with their signing certificate and send them, Outlook uses the sender's private key to encrypt the digital signature but sends the messages as clear text, unless they are encrypted separately. If users change this functionality by clearing the "Send clear text signed message when sending signed messages" option in the email Security section of the Trust Center, any recipients who are unable to access or use the sender's digital certificate will not be able to read the email messages.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Send all signed messages as clear signed messages" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value ClearSign is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Send all signed messages as clear signed messages" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47976r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17800'
  tag rid: 'SV-54023r1_rule'
  tag stig_id: 'DTOO264'
  tag gtitle: 'DTOO264 - Clear signed messages'
  tag fix_id: 'F-46909r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
