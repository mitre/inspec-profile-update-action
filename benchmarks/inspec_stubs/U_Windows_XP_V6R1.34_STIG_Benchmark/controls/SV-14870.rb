control 'SV-14870' do
  title 'Prevent printing over HTTP.'
  desc 'This check verifies that the system is configured to prevent the client computer’s ability to print over HTTP, which allows the computer to print to printers on the intranet as well as the Internet.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off printing over HTTP’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14259'
  tag rid: 'SV-14870r1_rule'
  tag gtitle: 'Printing Over HTTP'
  tag fix_id: 'F-13584r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
