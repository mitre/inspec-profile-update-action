control 'SV-25296' do
  title 'Disable Performance PerfTrack.'
  desc 'This setting prevents responsiveness events from being aggregated and sent to Microsoft.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\WDI\\{9c5a40da-b965-4fc3-8781-88dd50a6299d}\\

Value Name:  ScenarioExecutionEnabled

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Troubleshooting and Diagnostics -> Windows Performance PerfTrack -> “Enable/Disable PerfTrack” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-26857r1_chk'
  tag severity: 'low'
  tag gid: 'V-21970'
  tag rid: 'SV-25296r1_rule'
  tag gtitle: 'Disable PerfTrack'
  tag fix_id: 'F-22957r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
