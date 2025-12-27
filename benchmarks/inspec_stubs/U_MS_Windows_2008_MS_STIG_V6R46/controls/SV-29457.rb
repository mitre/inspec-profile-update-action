control 'SV-29457' do
  title 'Windows Installer – User Control'
  desc 'This check verifies that users are prevented from changing installation options.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name:  EnableUserControl

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Enable user control over installs” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-15329r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15685'
  tag rid: 'SV-29457r1_rule'
  tag gtitle: 'Windows Installer – User Control'
  tag fix_id: 'F-15552r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
