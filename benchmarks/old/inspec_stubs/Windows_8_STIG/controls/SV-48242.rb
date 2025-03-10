control 'SV-48242' do
  title 'Users must not be prompted to search Windows Update for device drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being prompted to search Windows Update for device drivers.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DontPromptForWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation -> "Turn off Windows Update device driver search prompt" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44921r1_chk'
  tag severity: 'low'
  tag gid: 'V-15703'
  tag rid: 'SV-48242r2_rule'
  tag stig_id: 'WN08-CC-000026'
  tag gtitle: 'Driver Install – Device Driver Search Prompt'
  tag fix_id: 'F-41378r2_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
