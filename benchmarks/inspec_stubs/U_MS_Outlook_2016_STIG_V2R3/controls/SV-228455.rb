control 'SV-228455' do
  title 'Send all signed messages as clear signed messages must be configured.'
  desc %q(This policy setting controls whether Outlook sends signed messages as clear text signed messages. If you enable this policy setting, the "Send clear text signed message when sending signed messages" option is selected in the E-mail Security section of the Trust Center. If you disable or do not configure this policy setting, when users sign e-mail messages with their digital signature and send them, Outlook uses the signature's private key to encrypt the digital signature but sends the messages as clear text, unless they are encrypted separately.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Send all signed messages as clear signed messages" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value ClearSign is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Send all signed messages as clear signed messages" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30688r497687_chk'
  tag severity: 'medium'
  tag gid: 'V-228455'
  tag rid: 'SV-228455r508021_rule'
  tag stig_id: 'DTOO264'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30673r497688_fix'
  tag 'documentable'
  tag legacy: ['SV-85855', 'V-71231']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
