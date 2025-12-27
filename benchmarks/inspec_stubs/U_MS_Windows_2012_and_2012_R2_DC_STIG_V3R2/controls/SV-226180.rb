control 'SV-226180' do
  title 'Responsiveness events must be prevented from being aggregated and sent to Microsoft.'
  desc 'Some features may communicate with the vendor, sending system information or downloading data or components for the feature.  Turning off this capability will prevent potentially sensitive information from being sent outside the enterprise and uncontrolled updates to the system.  
This setting prevents responsiveness events from being aggregated and sent to Microsoft.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\\

Value Name: ScenarioExecutionEnabled

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Windows Performance PerfTrack -> "Enable/Disable PerfTrack" to "Disabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27882r475863_chk'
  tag severity: 'low'
  tag gid: 'V-226180'
  tag rid: 'SV-226180r569184_rule'
  tag stig_id: 'WN12-CC-000068'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-27870r475864_fix'
  tag 'documentable'
  tag legacy: ['SV-53128', 'V-21970']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
