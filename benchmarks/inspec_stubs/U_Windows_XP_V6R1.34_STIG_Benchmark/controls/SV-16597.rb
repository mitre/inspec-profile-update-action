control 'SV-16597' do
  title 'Classic Logon'
  desc 'This check verifies that users will always use the classic logon screen.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Logon “Always use classic logon” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-15680'
  tag rid: 'SV-16597r1_rule'
  tag gtitle: 'Classic Logon'
  tag fix_id: 'F-15547r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
