control 'SV-254381' do
  title 'Windows Server 2022 Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> Allow Basic authentication to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57866r848957_chk'
  tag severity: 'high'
  tag gid: 'V-254381'
  tag rid: 'SV-254381r877395_rule'
  tag stig_id: 'WN22-CC-000500'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-57817r848958_fix'
  tag 'documentable'
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
