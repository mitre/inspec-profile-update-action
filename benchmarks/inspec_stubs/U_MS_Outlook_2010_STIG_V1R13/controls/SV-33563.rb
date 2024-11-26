control 'SV-33563' do
  title 'Message formats must be set to use SMime.'
  desc 'E-mail typically travels over open networks and is passed from server to server. Messages are therefore vulnerable to interception, and attackers might read or alter their contents. It is therefore important to have a mechanism for signing messages and providing end-to-end encryption.
Outlook supports three formats for encrypting and signing messages: S/MIME, Exchange, and Fortezza. By default, Outlook only uses S/MIME to encrypt and sign messages. If your organization has policies that mandate the use of specific encryption formats, allowing users to choose freely between these formats could cause them to violate such policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “Message Formats” must be set to “Enabled (S\\MIME)”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value MsgFormats is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cryptography “Message Formats” to “Enabled (S\\MIME)”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34024r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17755'
  tag rid: 'SV-33563r1_rule'
  tag stig_id: 'DTOO260 - Outlook'
  tag gtitle: 'DTOO260 - SMime message formats'
  tag fix_id: 'F-29709r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
