control 'SV-14869' do
  title 'Search Companion will be prevented from automatically downloading content updates.'
  desc 'This check verifies that the system is configured to prevent Search Companion from automatically downloading content updates during local and Internet searches.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication setting ‘Turn off Search Companion content file updates’ to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14258'
  tag rid: 'SV-14869r1_rule'
  tag gtitle: 'Search Companion Content File Updates'
  tag fix_id: 'F-13583r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
