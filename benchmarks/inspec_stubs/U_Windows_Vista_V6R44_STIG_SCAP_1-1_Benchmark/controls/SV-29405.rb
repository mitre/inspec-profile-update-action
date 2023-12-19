control 'SV-29405' do
  title 'Terminal Services / Remote Desktop Service - Prevent password saving in the Remote Desktop Client'
  desc 'This check verifies that the system is configured to prevent Users from saving passwords in the Remote Desktop Client.'
  desc 'fix', 'Vista - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services-> Remote Desktop Connection Client “Do not allow passwords to be saved” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-14247'
  tag rid: 'SV-29405r1_rule'
  tag gtitle: 'TS/RDS - Prevent Password Saving'
  tag fix_id: 'F-13572r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
