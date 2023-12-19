control 'SV-48215' do
  title 'Windows must be prevented from using Windows Update to search for drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents Windows from searching Windows Update for device drivers when no local drivers for a device are present.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DontSearchWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Windows Update device driver searching" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44894r1_chk'
  tag severity: 'medium'
  tag gid: 'V-14261'
  tag rid: 'SV-48215r1_rule'
  tag stig_id: 'WN08-CC-000047'
  tag gtitle: 'Windows Update Device Drive Searching'
  tag fix_id: 'F-41351r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
