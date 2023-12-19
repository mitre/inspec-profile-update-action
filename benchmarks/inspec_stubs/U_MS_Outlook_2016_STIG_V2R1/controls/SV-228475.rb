control 'SV-228475' do
  title 'Replies or forwards to signed/encrypted messages must be signed/encrypted.'
  desc 'This policy setting controls whether replies and forwards to signed/encrypted mail should also be signed/encrypted. If you enable this policy setting, signing/encryption will be turned on when replying/forwarding a signed or encrypted message, even if the user is not configured for SMIME. If you disable or do not configure this policy setting, signing/encryption is not enforced.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Replies or forwards to signed/encrypted messages are signed/encrypted" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\security

Criteria: If the value NoCheckOnSessionSecurity is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Security -> Cryptography "Replies or forwards to signed/encrypted messages are signed/encrypted" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30708r497747_chk'
  tag severity: 'medium'
  tag gid: 'V-228475'
  tag rid: 'SV-228475r508021_rule'
  tag stig_id: 'DTOO317'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30693r497748_fix'
  tag 'documentable'
  tag legacy: ['V-71275', 'SV-85899']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
