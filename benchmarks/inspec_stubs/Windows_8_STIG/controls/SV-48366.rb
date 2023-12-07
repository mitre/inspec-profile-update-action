control 'SV-48366' do
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45035r1_chk'
  tag severity: 'high'
  tag gid: 'V-36718'
  tag rid: 'SV-48366r2_rule'
  tag stig_id: 'WN08-CC-000126'
  tag gtitle: 'WINCC-000126'
  tag fix_id: 'F-41497r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
