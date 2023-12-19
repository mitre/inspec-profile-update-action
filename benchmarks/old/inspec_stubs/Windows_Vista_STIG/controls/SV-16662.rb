control 'SV-16662' do
  title 'Meeting Space'
  desc 'This check verifies that Windows Meeting Space is disabled.'
  desc 'fix', 'Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Meeting Space “Turn off Windows Meeting Space” to “Enabled”'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15723'
  tag rid: 'SV-16662r2_rule'
  tag gtitle: 'Meeting Space'
  tag fix_id: 'F-15615r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
