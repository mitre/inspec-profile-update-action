control 'SV-226148' do
  title 'Windows Update must be prevented from searching for point and print drivers.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent Windows from searching Windows Update for point and print drivers.  Only the local driver store and server driver cache will be searched.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Printers\\

Value Name: DoNotInstallCompatibleDriverFromWindowsUpdate

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Printers -> "Extend Point and Print connection to search Windows Update" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27850r475767_chk'
  tag severity: 'low'
  tag gid: 'V-226148'
  tag rid: 'SV-226148r794467_rule'
  tag stig_id: 'WN12-CC-000016'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27838r475768_fix'
  tag 'documentable'
  tag legacy: ['SV-53184', 'V-21963']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
