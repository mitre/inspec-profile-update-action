control 'SV-25297' do
  title 'Prevent the Application Compatibility Program Inventory from collecting data and sending the information to Microsoft.'
  desc 'This setting will prevent the Program Inventory from collecting data about a system and sending the information to Microsoft.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\AppCompat\\

Value Name:  DisableInventory

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Application Compatibility -> “Turn off Program Inventory” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26858r1_chk'
  tag severity: 'low'
  tag gid: 'V-21971'
  tag rid: 'SV-25297r1_rule'
  tag gtitle: 'Application Compatibility Program Inventory'
  tag fix_id: 'F-22959r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
