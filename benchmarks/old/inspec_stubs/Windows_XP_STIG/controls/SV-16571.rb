control 'SV-16571' do
  title 'Terminal Services - Prevent password saving in the Remote Desktop Client'
  desc 'This check verifies that the system is configured to prevent Users from saving passwords in the Remote Desktop Client.'
  desc 'fix', 'XP - Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Terminal Services-> Client “Do not allow passwords to be saved” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-14247'
  tag rid: 'SV-16571r1_rule'
  tag gtitle: 'TS/RDS - Prevent Password Saving'
  tag fix_id: 'F-15528r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
