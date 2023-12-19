control 'SV-224958' do
  title 'The Windows Remote Management (WinRM) client must not use Basic authentication.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26649r465776_chk'
  tag severity: 'high'
  tag gid: 'V-224958'
  tag rid: 'SV-224958r569186_rule'
  tag stig_id: 'WN16-CC-000500'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-26637r465777_fix'
  tag 'documentable'
  tag legacy: ['V-73593', 'SV-88257']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
