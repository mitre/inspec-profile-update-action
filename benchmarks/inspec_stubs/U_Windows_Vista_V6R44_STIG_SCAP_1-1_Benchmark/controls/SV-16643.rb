control 'SV-16643' do
  title 'Handwriting Recognition Error Reporting (Tablet PCs)'
  desc 'This check verifies that errors in handwriting recognition on Tablet PCs are not reported to Microsoft.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Internet Communication Management -> Internet Communications settings “Turn off handwriting recognition error reporting” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15704'
  tag rid: 'SV-16643r1_rule'
  tag gtitle: 'Handwriting Recognition Error Reporting'
  tag fix_id: 'F-15596r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
