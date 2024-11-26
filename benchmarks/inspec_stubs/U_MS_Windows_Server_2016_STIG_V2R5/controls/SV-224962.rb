control 'SV-224962' do
  title 'The Windows Remote Management (WinRM) service must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.

'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Service >> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26653r465788_chk'
  tag severity: 'medium'
  tag gid: 'V-224962'
  tag rid: 'SV-224962r852337_rule'
  tag stig_id: 'WN16-CC-000540'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-26641r465789_fix'
  tag satisfies: ['SRG-OS-000393-GPOS-00173', 'SRG-OS-000394-GPOS-00174']
  tag 'documentable'
  tag legacy: ['SV-88265', 'V-73601']
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
