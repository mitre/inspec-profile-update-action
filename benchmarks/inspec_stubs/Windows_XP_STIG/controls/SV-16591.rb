control 'SV-16591' do
  title 'Disable Internet File Association Service'
  desc 'This check verifies that unhandled file associations will not use the Microsoft Web service to find an application.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Internet File Association service” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15674'
  tag rid: 'SV-16591r1_rule'
  tag gtitle: 'Internet File Association Service'
  tag fix_id: 'F-15541r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
