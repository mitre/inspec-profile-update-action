control 'SV-253411' do
  title 'The Windows Installer feature "Always install with elevated privileges" must be disabled.'
  desc 'Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: AlwaysInstallElevated

Value Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Always install with elevated privileges" to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56864r829315_chk'
  tag severity: 'high'
  tag gid: 'V-253411'
  tag rid: 'SV-253411r829317_rule'
  tag stig_id: 'WN11-CC-000315'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-56814r829316_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
