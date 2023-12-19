control 'SV-48548' do
  title 'Windows Update must be prevented from searching for point and print drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent Windows from searching Windows Update for point and print drivers.  Only the local driver store and server driver cache will be searched.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DoNotInstallCompatibleDriverFromWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Printers -> "Extend Point and Print connection to search Windows Update" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45108r2_chk'
  tag severity: 'low'
  tag gid: 'V-21963'
  tag rid: 'SV-48548r2_rule'
  tag stig_id: 'WN08-CC-000016'
  tag gtitle: 'Windows Update Point and Print Driver Search'
  tag fix_id: 'F-41573r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
