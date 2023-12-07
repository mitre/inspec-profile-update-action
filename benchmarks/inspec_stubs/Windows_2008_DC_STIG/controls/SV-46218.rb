control 'SV-46218' do
  title 'The Windows Installer Always install with elevated privileges must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-43428r1_chk'
  tag severity: 'high'
  tag gid: 'V-34974'
  tag rid: 'SV-46218r1_rule'
  tag stig_id: 'WINCC-000001'
  tag gtitle: 'Always Install with Elevated Privileges Disabled'
  tag fix_id: 'F-39547r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
