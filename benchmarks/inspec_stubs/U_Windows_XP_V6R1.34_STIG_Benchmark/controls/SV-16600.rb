control 'SV-16600' do
  title 'Windows Explorer – Shell Protocol Protected Mode'
  desc 'This check verifies that the shell protocol is run in protected mode.  (This allows applications to only open limited folders.)'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Explorer “Turn off shell protocol protected mode” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15683'
  tag rid: 'SV-16600r1_rule'
  tag gtitle: 'Windows Explorer – Shell Protocol Protected Mode'
  tag fix_id: 'F-15550r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
