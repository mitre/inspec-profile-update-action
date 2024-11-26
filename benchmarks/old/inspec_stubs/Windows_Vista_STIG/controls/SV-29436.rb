control 'SV-29436' do
  title 'Internet Connection Wizard ISP Downloads'
  desc 'This check verifies that the Internet Connection Wizard cannot download a list of Internet Service Providers (ISPs) from Microsoft.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Internet Connection Wizard if URL connection is referring to Microsoft.com” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15673'
  tag rid: 'SV-29436r1_rule'
  tag gtitle: 'Internet Connection Wizard ISP Downloads'
  tag fix_id: 'F-15540r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
