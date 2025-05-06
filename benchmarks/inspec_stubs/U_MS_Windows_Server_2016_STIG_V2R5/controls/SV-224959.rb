control 'SV-224959' do
  title 'The Windows Remote Management (WinRM) client must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26650r465779_chk'
  tag severity: 'medium'
  tag gid: 'V-224959'
  tag rid: 'SV-224959r852336_rule'
  tag stig_id: 'WN16-CC-000510'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-26638r465780_fix'
  tag satisfies: ['SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['SV-88259', 'V-73595']
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
