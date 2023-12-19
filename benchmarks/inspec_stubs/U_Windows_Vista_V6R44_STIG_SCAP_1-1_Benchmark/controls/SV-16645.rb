control 'SV-16645' do
  title 'Power Mgmt – Password Wake When Plugged In'
  desc 'This check verifies that the user is prompted for a password on resume from sleep (Plugged In).'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings “Require a Password When a Computer Wakes (Plugged In)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15706'
  tag rid: 'SV-16645r1_rule'
  tag gtitle: 'Power Mgmt – Password Wake When Plugged In'
  tag fix_id: 'F-15598r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
