control 'SV-16596' do
  title 'Windows Movie Maker Online Hosting'
  desc 'This check verifies that movies can not be sent to a video hosting provider on the web.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Windows Movie Maker saving to online video hosting provider” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15679'
  tag rid: 'SV-16596r1_rule'
  tag gtitle: 'Windows Movie Maker Online Hosting'
  tag fix_id: 'F-15546r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
