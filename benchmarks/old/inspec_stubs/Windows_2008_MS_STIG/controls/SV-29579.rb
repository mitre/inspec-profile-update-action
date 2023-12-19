control 'SV-29579' do
  title 'Windows Mail – Disable Application'
  desc 'This check verifies that Windows Mail will be disabled.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows Mail\\

Value Name:	ManualLaunchAllowed

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Mail “Turn off Windows Mail application” to “Enabled”'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15409r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15721'
  tag rid: 'SV-29579r1_rule'
  tag gtitle: 'Windows Mail – Disable Application'
  tag fix_id: 'F-15613r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
