control 'SV-25267' do
  title 'Unsigned gadgets must not be installed.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  This setting prevents unsigned gadgets from being installed.'
  desc 'check', 'If Desktop Gadgets have been disabled, this is NA.
Verify the following registry value to determine if Desktop Gadgets have been disabled:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar\\

Value Name:  TurnOffSidebar

Type:  REG_DWORD
Value:  1

If Desktop Gadgets have not been disabled and the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar\\

Value Name:  TurnOffUnsignedGadgets

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Desktop Gadgets ->  "Restrict unpacking and installation of gadgets that are not digitally signed" to "Enabled".   

To turn off Desktop Gadgets completely, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Desktop Gadgets -> "Turn off desktop gadgets" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-57969r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15724'
  tag rid: 'SV-25267r2_rule'
  tag gtitle: 'Gadgets – Unsigned Gadgets'
  tag fix_id: 'F-62293r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
