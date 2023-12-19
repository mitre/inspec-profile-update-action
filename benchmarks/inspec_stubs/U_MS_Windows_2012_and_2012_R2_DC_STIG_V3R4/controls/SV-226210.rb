control 'SV-226210' do
  title 'The Windows Installer Always install with elevated privileges option must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges.  Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Always install with elevated privileges" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27912r475953_chk'
  tag severity: 'high'
  tag gid: 'V-226210'
  tag rid: 'SV-226210r794474_rule'
  tag stig_id: 'WN12-CC-000116'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27900r475954_fix'
  tag 'documentable'
  tag legacy: ['SV-52954', 'V-34974']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
