control 'SV-33570' do
  title 'All signed messages as clear signed messages must be configured.'
  desc "When users sign e-mail messages with their digital signature and send them, Outlook uses the signature's private key to encrypt the digital signature but sends the messages as clear text, unless they are encrypted separately. If users change this functionality by clearing the Send clear text signed message when sending signed messages option in the E-mail Security section of the Trust Center, any recipients who are unable to access or use the sender's digital certificate will not be able to read the e-mail messages."
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “Send all signed messages as clear signed messages” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value ClearSign is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “Send all signed messages as clear signed messages” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34032r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17800'
  tag rid: 'SV-33570r1_rule'
  tag stig_id: 'DTOO264 - Outlook'
  tag gtitle: 'DTOO264 - Clear signed messages'
  tag fix_id: 'F-29715r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
