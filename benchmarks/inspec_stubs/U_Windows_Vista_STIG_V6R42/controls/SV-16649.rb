control 'SV-16649' do
  title 'Online Assistance – Untrusted Content'
  desc 'This check verifies that untrusted content is not rendered for online assistance.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Assistance\\Client\\1.0\\

Value Name:	NoUntrustedContent

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Online Assistance “Turn off Untrusted Content” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-15398r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15710'
  tag rid: 'SV-16649r2_rule'
  tag gtitle: 'Online Assistance – Untrusted Content'
  tag fix_id: 'F-15602r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
