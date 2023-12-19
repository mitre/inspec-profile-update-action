control 'SV-54004' do
  title 'Message formats must be set to use SMime.'
  desc 'Email typically travels over open networks and is passed from server to server. Messages are therefore vulnerable to interception, and attackers might read or alter their contents. It is therefore important to have a mechanism for signing messages and providing end-to-end encryption.
Outlook supports three formats for encrypting and signing messages: S/MIME, Exchange, and Fortezza. By default, Outlook only uses S/MIME to encrypt and sign messages. When an organization has policies that mandate the use of specific encryption formats, allowing users to choose freely between these formats could cause them to violate such policies.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Message Formats" is set to "Enabled (S\\MIME)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\security

Criteria: If the value MsgFormats is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Security -> Cryptography "Message Formats" to "Enabled (S\\MIME)".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47974r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17755'
  tag rid: 'SV-54004r1_rule'
  tag stig_id: 'DTOO260'
  tag gtitle: 'DTOO260 - SMime message formats'
  tag fix_id: 'F-46893r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
