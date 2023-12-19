control 'SV-16590' do
  title 'Internet Connection Wizard ISP Downloads'
  desc 'This check verifies that the Internet Connection Wizard cannot download a list of Internet Service Providers (ISPs) from Microsoft.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows XP'
  tag severity: 'low'
  tag gid: 'V-15673'
  tag rid: 'SV-16590r1_rule'
  tag gtitle: 'Internet Connection Wizard ISP Downloads'
  tag fix_id: 'F-15540r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
