control 'SV-253417' do
  title 'The Windows Remote Management (WinRM) client must not allow unencrypted traffic.'
  desc 'Unencrypted remote access to a system can allow sensitive information to be compromised. Windows remote management connections must be encrypted to prevent this.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\

Value Name: AllowUnencryptedTraffic

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Remote Management (WinRM) >> WinRM Client >> "Allow unencrypted traffic" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56870r829333_chk'
  tag severity: 'medium'
  tag gid: 'V-253417'
  tag rid: 'SV-253417r829335_rule'
  tag stig_id: 'WN11-CC-000335'
  tag gtitle: 'SRG-OS-000393-GPOS-00173'
  tag fix_id: 'F-56820r829334_fix'
  tag 'documentable'
  tag cci: ['CCI-002890']
  tag nist: ['MA-4 (6)']
end
