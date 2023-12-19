control 'SV-48451' do
  title 'Device driver searches using Windows Update must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent the system from searching Windows Update for device drivers.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: SearchOrderConfig

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify Search Order for device driver source locations" to "Enabled: Do not search Windows Update".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45115r2_chk'
  tag severity: 'low'
  tag gid: 'V-21965'
  tag rid: 'SV-48451r2_rule'
  tag stig_id: 'WN08-CC-000024'
  tag gtitle: 'Prevent Windows Update for device driver search'
  tag fix_id: 'F-41579r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
