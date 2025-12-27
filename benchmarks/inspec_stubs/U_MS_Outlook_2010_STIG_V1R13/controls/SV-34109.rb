control 'SV-34109' do
  title 'Replies or forwards to signed/encrypted messages must be signed/encrypted.'
  desc 'This setting controls whether replies and forwards to signed/encrypted mail should also be signed/encrypted.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cyrptography “Replies or forwards to signed/encrypted messages are signed/encrypted” must be set to “Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\security

Criteria: If the value NoCheckOnSessionSecurity is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Security -> Cyrptography “Replies or forwards to signed/encrypted messages are signed/encrypted” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26637'
  tag rid: 'SV-34109r1_rule'
  tag stig_id: 'DTOO317 - Outlook'
  tag gtitle: 'DTOO317 - Signed/encrypted messages'
  tag fix_id: 'F-29923r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
