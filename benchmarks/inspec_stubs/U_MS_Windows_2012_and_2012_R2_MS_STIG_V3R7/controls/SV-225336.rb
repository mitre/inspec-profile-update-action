control 'SV-225336' do
  title 'Users must not be prompted to search Windows Update for device drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents users from being prompted to search Windows Update for device drivers.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: DontPromptForWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Driver Installation -> "Turn off Windows Update device driver search prompt" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 MS'
  tag check_id: 'C-27035r471350_chk'
  tag severity: 'low'
  tag gid: 'V-225336'
  tag rid: 'SV-225336r852204_rule'
  tag stig_id: 'WN12-CC-000026'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27023r471351_fix'
  tag 'documentable'
  tag legacy: ['SV-53115', 'V-15703']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
