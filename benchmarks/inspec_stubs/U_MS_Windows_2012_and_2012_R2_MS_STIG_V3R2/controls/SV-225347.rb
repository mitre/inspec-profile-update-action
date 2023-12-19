control 'SV-225347' do
  title 'Windows must be prevented from using Windows Update to search for drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents Windows from searching Windows Update for device drivers when no local drivers for a device are present.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DontSearchWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings -> "Turn off Windows Update device driver searching" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27046r471383_chk'
  tag severity: 'medium'
  tag gid: 'V-225347'
  tag rid: 'SV-225347r569185_rule'
  tag stig_id: 'WN12-CC-000047'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27034r471384_fix'
  tag 'documentable'
  tag legacy: ['SV-53000', 'V-14261']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
