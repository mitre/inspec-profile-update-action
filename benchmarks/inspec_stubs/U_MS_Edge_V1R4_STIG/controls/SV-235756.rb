control 'SV-235756' do
  title 'The Password Manager must be disabled.'
  desc 'Enable Microsoft Edge to save user passwords.

If this policy is enabled, users can save their passwords in Microsoft Edge. The next time the user visits the site, Microsoft Edge will enter the password automatically.'
  desc 'check', 'The policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Password manager and protection/Enable saving passwords to the password manager" must be set to "disabled".

Use the Windows Registry Editor to navigate to the following key:
HKLM\\SOFTWARE\\Policies\\Microsoft\\Edge

If the value for "PasswordManagerEnabled" is not set to "REG_DWORD = 0", this is a finding.'
  desc 'fix', 'Set the policy value for "Computer Configuration/Administrative Templates/Microsoft Edge/Password manager and protection/Enable saving passwords to the password manager" to "disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Edge'
  tag check_id: 'C-38975r626464_chk'
  tag severity: 'medium'
  tag gid: 'V-235756'
  tag rid: 'SV-235756r626523_rule'
  tag stig_id: 'EDGE-00-000043'
  tag gtitle: 'SRG-APP-000400'
  tag fix_id: 'F-38938r626465_fix'
  tag 'documentable'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
end
