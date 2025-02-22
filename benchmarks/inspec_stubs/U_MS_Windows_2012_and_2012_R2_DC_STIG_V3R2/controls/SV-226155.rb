control 'SV-226155' do
  title 'Device driver searches using Windows Update must be prevented.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting will prevent the system from searching Windows Update for device drivers.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path:  \\Software\\Policies\\Microsoft\\Windows\\DriverSearching\\

Value Name: SearchOrderConfig

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Device Installation -> "Specify search order for device driver source locations" to "Enabled: Do not search Windows Update".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27857r475788_chk'
  tag severity: 'low'
  tag gid: 'V-226155'
  tag rid: 'SV-226155r569184_rule'
  tag stig_id: 'WN12-CC-000024'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-27845r475789_fix'
  tag 'documentable'
  tag legacy: ['SV-53186', 'V-21965']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
