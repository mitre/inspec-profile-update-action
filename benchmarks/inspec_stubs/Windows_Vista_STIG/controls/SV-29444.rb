control 'SV-29444' do
  title 'Windows Movie Maker Web Links'
  desc 'This check verifies that the links to web sites in Windows Movie Maker will not be available.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communication settings “Turn off Windows Movie Maker online Web links” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15678'
  tag rid: 'SV-29444r1_rule'
  tag gtitle: 'Windows Movie Maker Web Links'
  tag fix_id: 'F-15545r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
