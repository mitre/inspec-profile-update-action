control 'SV-16587' do
  title 'Error Reporting - Display Error Notification'
  desc 'This check verifies that users will not be given a choice to report errors.'
  desc 'check', 'If the following registry value doesn’t exist or its value is not set to 0, then this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\PCHealth\\ErrorReporting\\
Value Name: ShowUI
Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Error Reporting “Display Error Notification” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag check_id: 'C-15314r1_chk'
  tag severity: 'low'
  tag gid: 'V-15670'
  tag rid: 'SV-16587r1_rule'
  tag gtitle: 'Error Reporting - Display Error Notification'
  tag fix_id: 'F-15537r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
