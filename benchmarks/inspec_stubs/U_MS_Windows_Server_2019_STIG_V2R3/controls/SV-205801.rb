control 'SV-205801' do
  title 'Windows Server 2019 must prevent users from changing installation options.'
  desc 'Installation options for applications are typically controlled by administrators. This setting prevents users from changing installation options that may bypass security features.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0x00000000 (0)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Windows Installer >> "Allow user control over installs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2019'
  tag check_id: 'C-6066r355765_chk'
  tag severity: 'medium'
  tag gid: 'V-205801'
  tag rid: 'SV-205801r569188_rule'
  tag stig_id: 'WN19-CC-000420'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-6066r355766_fix'
  tag 'documentable'
  tag legacy: ['V-93199', 'SV-103287']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
