control 'SV-32420' do
  title 'Non-administrators will be prevented from applying vendor signed updates.'
  desc 'This check verifies that users are prevented from applying vendor signed updates.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Installer\\

Value Name:  DisableLUAPatching

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Installer “Prohibit non-administrators from applying vendor signed updates” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-15330r1_chk'
  tag severity: 'low'
  tag gid: 'V-15686'
  tag rid: 'SV-32420r1_rule'
  tag gtitle: 'Windows Installer – Vendor Signed Updates'
  tag fix_id: 'F-15553r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
