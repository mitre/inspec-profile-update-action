control 'SV-16660' do
  title 'Windows Mail – Disable Application'
  desc 'This check verifies that Windows Mail will be disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Mail “Turn off Windows Mail application” to “Enabled”'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15721'
  tag rid: 'SV-16660r2_rule'
  tag gtitle: 'Windows Mail – Disable Application'
  tag fix_id: 'F-15613r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
