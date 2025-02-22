control 'SV-16649' do
  title 'Online Assistance – Untrusted Content'
  desc 'This check verifies that untrusted content is not rendered for online assistance.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Online Assistance “Turn off Untrusted Content” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15710'
  tag rid: 'SV-16649r2_rule'
  tag gtitle: 'Online Assistance – Untrusted Content'
  tag fix_id: 'F-15602r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
