control 'SV-224961' do
  title 'The Windows Remote Management (WinRM) service must not use Basic authentication.'
  desc 'Basic authentication uses plain-text passwords that could be used to compromise a system. Disabling Basic authentication will reduce this potential.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowBasic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow Basic authentication" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows Server 2016'
  tag check_id: 'C-26652r465785_chk'
  tag severity: 'high'
  tag gid: 'V-224961'
  tag rid: 'SV-224961r569186_rule'
  tag stig_id: 'WN16-CC-000530'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-26640r465786_fix'
  tag 'documentable'
  tag legacy: ['SV-88263', 'V-73599']
  tag cci: ['CCI-000877']
  tag nist: ['MA-4 c']
end
