control 'SV-48348' do
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45020r1_chk'
  tag severity: 'high'
  tag gid: 'V-36712'
  tag rid: 'SV-48348r2_rule'
  tag stig_id: 'WN08-CC-000123'
  tag gtitle: 'WINCC-000123'
  tag fix_id: 'F-41481r1_fix'
  tag 'documentable'
  tag ia_controls: 'IAIA-1'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
