control 'SV-226216' do
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27918r475971_chk'
  tag severity: 'high'
  tag gid: 'V-226216'
  tag rid: 'SV-226216r794449_rule'
  tag stig_id: 'WN12-CC-000123'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-27906r475972_fix'
  tag 'documentable'
  tag legacy: ['SV-51752', 'V-36712']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
