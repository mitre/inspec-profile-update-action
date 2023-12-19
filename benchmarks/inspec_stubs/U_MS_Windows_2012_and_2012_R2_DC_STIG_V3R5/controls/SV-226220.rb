control 'SV-226220' do
  title 'The Windows Remote Management (WinRM) service must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote management connections must be encrypted to prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Service\\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Service -> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27922r475983_chk'
  tag severity: 'medium'
  tag gid: 'V-226220'
  tag rid: 'SV-226220r852117_rule'
  tag stig_id: 'WN12-CC-000127'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-27910r475984_fix'
  tag 'documentable'
  tag legacy: ['SV-51756', 'V-36719']
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
