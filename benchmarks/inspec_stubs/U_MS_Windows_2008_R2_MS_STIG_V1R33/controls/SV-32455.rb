control 'SV-32455' do
  title 'Device driver searches using Windows Update will be prevented.'
  desc 'This setting will prevent the system from searching Windows Update for device drivers.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:   \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name:  SearchOrderConfig

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> “Specify Search Order for device driver source locations” to “Enabled: Do not search Windows Update”.'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-26853r1_chk'
  tag severity: 'low'
  tag gid: 'V-21965'
  tag rid: 'SV-32455r1_rule'
  tag gtitle: 'Prevent Windows Update for device driver search'
  tag fix_id: 'F-22952r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
