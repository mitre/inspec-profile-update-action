control 'SV-225399' do
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain text passwords that could be used to compromise a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27098r471539_chk'
  tag severity: 'high'
  tag gid: 'V-225399'
  tag rid: 'SV-225399r569185_rule'
  tag stig_id: 'WN12-CC-000126'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-27086r471540_fix'
  tag 'documentable'
  tag legacy: ['V-36718', 'SV-51755']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
