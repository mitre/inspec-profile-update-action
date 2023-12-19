control 'SV-226209' do
  title 'Users must be prevented from changing installation options.'
  desc 'Installation options for applications are typically controlled by administrators.  This setting prevents users from changing installation options that may bypass security features.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name: EnableUserControl

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer -> "Allow user control over installs" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27911r475950_chk'
  tag severity: 'medium'
  tag gid: 'V-226209'
  tag rid: 'SV-226209r852112_rule'
  tag stig_id: 'WN12-CC-000115'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27899r475951_fix'
  tag 'documentable'
  tag legacy: ['SV-53061', 'V-15685']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
