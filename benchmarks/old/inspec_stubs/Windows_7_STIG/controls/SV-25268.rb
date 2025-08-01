control 'SV-25268' do
  title 'The More Gadgets link must be disabled.'
  desc 'Uncontrolled installation of applications can introduce various issues, including system instability, and allow access to sensitive information.  Installation of applications must be controlled by the enterprise.  This setting prevents access to gadgets through the More Gadgets link.'
  desc 'check', 'If Desktop Gadgets have been disabled, this is NA.
Verify the following registry value to determine if Desktop Gadgets have been disabled:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar\\

Value Name:  TurnOffSidebar

Type:  REG_DWORD
Value:  1

If Desktop Gadgets have not been disabled and the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Windows\\Sidebar\\

Value Name:  OverrideMoreGadgetsLink

Type:  REG_SZ
Value:  about:blank'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Desktop Gadgets -> "Override the More Gadgets Link" to "Enabled" with "about:blank" entered in the "Override Gadget Location".

To turn off Desktop Gadgets completely, configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Desktop Gadgets -> "Turn off desktop gadgets" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-57971r2_chk'
  tag severity: 'medium'
  tag gid: 'V-15725'
  tag rid: 'SV-25268r2_rule'
  tag gtitle: 'Gadgets – More Gadgets Link'
  tag fix_id: 'F-62295r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
