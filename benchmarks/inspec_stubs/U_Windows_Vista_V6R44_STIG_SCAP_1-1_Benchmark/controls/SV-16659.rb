control 'SV-16659' do
  title 'Windows Mail – Communities'
  desc 'This check verifies that Windows Mail will not check newsgroups for Communities support.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Mail “Turn off the communities features” to “Enabled”'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15720'
  tag rid: 'SV-16659r2_rule'
  tag gtitle: 'Windows Mail – Communities'
  tag fix_id: 'F-15612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
