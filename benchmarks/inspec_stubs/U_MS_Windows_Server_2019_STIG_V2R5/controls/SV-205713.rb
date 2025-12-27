control 'SV-205713' do
  title 'Windows Server 2019 Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5978r355057_chk'
  tag severity: 'high'
  tag gid: 'V-205713'
  tag rid: 'SV-205713r569188_rule'
  tag stig_id: 'WN19-CC-000500'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-5978r355058_fix'
  tag 'documentable'
  tag legacy: ['V-93507', 'SV-103593']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
