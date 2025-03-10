control 'SV-25301' do
  title 'Prevent the system from joining a homegroup.'
  desc 'This setting will prevent a system from being joined to a homegroup.  Homegroups are a method of sharing data and printers on a home network.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Homegroup\\

Value Name:  DisableHomeGroup

Type:  REG_DWORD
Value:  1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> HomeGroup -> “Prevent the computer from joining a homegroup” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26861r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21975'
  tag rid: 'SV-25301r1_rule'
  tag gtitle: 'Prevent Joining Homegroup'
  tag fix_id: 'F-22967r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
