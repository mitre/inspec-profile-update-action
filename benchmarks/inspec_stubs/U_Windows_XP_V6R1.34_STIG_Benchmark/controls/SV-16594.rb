control 'SV-16594' do
  title 'Windows Movie Maker Codec Downloads'
  desc 'This check verifies that the codecs will not be automatically downloaded for Windows Movie Maker.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Windows Movie Maker automatic codec downloads” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15677'
  tag rid: 'SV-16594r1_rule'
  tag gtitle: 'Windows Movie Maker Codec Downloads'
  tag fix_id: 'F-15544r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
