control 'SV-254374' do
  title 'Windows Server 2022 must disable the Windows Installer Always install with elevated privileges option.'
  desc 'Standard user accounts must not be granted elevated privileges. Enabling Windows Installer to elevate privileges when installing applications can allow malicious persons and applications to gain full control of a system.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: AlwaysInstallElevated

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> Always install with elevated privileges to "Disabled".'
  impact 0.7
  ref 'DPMS Target Microsoft Windows Server 2022'
  tag check_id: 'C-57859r848936_chk'
  tag severity: 'high'
  tag gid: 'V-254374'
  tag rid: 'SV-254374r848938_rule'
  tag stig_id: 'WN22-CC-000430'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-57810r848937_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
