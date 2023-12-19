control 'SV-16638' do
  title 'Network – Windows Connect Now Wizards'
  desc 'This check verifies that access to the Windows Connect Now wizards is disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Windows Connect Now “Prohibit Access of the Windows Connect Now wizards” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15699'
  tag rid: 'SV-16638r1_rule'
  tag gtitle: 'Network – Windows Connect Now Wizards'
  tag fix_id: 'F-15591r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
