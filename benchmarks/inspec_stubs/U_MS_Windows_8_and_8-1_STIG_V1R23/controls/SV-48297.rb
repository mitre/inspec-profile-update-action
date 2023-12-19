control 'SV-48297' do
  title 'Device driver updates must only search managed servers, not Windows Update.'
  desc 'Uncontrolled system updates can introduce issues to a system.  Obtaining update components from an outside source may also potentially provide sensitive information outside of the enterprise.  Device driver updates must be obtained from an internal source.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DriverServerSelection

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify the search server for device driver updates" to "Enabled" with "Search Managed Server" selected.'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44975r1_chk'
  tag severity: 'low'
  tag gid: 'V-36678'
  tag rid: 'SV-48297r2_rule'
  tag stig_id: 'WN08-CC-000025'
  tag gtitle: 'WINCC-000025'
  tag fix_id: 'F-41432r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
