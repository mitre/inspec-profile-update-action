control 'SV-205711' do
  title 'Windows Server 2019 Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2019'
  tag check_id: 'C-5976r355051_chk'
  tag severity: 'high'
  tag gid: 'V-205711'
  tag rid: 'SV-205711r877395_rule'
  tag stig_id: 'WN19-CC-000470'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-5976r355052_fix'
  tag 'documentable'
  tag legacy: ['V-93503', 'SV-103589']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
