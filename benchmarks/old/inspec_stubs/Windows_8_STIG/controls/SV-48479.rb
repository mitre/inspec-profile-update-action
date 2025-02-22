control 'SV-48479' do
  title 'The system must be prevented from joining a homegroup.'
  desc 'Homegroups are a method of sharing data and printers on a home network.  This setting will prevent a system from being joined to a homegroup.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Homegroup\\

Value Name: DisableHomeGroup

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> HomeGroup -> "Prevent the computer from joining a homegroup" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45140r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21975'
  tag rid: 'SV-48479r2_rule'
  tag stig_id: 'WN08-CC-000094'
  tag gtitle: 'Prevent Joining Homegroup'
  tag fix_id: 'F-41603r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
