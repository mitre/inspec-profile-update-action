control 'SV-48350' do
  title 'The Windows Remote Management (WinRM) client must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised.  Windows remote management connections must be encrypted to prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowUnencryptedTraffic

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Remote Management (WinRM) -> WinRM Client -> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45022r1_chk'
  tag severity: 'medium'
  tag gid: 'V-36713'
  tag rid: 'SV-48350r2_rule'
  tag stig_id: 'WN08-CC-000124'
  tag gtitle: 'WINCC-000124'
  tag fix_id: 'F-41482r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECCT-1'
  tag cci: ['CCI-002890', 'CCI-003123']
  tag nist: ['MA-4 (6)', 'MA-4 (6)']
end
