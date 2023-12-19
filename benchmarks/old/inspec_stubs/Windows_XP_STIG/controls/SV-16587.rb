control 'SV-16587' do
  title 'Error Reporting - Display Error Notification'
  desc 'This check verifies that users will not be given a choice to report errors.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Error Reporting “Display Error Notification” to “Disabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-15670'
  tag rid: 'SV-16587r1_rule'
  tag gtitle: 'Error Reporting - Display Error Notification'
  tag fix_id: 'F-15537r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
