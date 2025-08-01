control 'SV-29440' do
  title 'Windows Registration Wizard'
  desc 'This check verifies that the Windows Registration Wizard is blocked from online registration.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Registration if URL connection is referring to Microsoft.com” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15675'
  tag rid: 'SV-29440r1_rule'
  tag gtitle: 'Windows Registration Wizard'
  tag fix_id: 'F-15542r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
