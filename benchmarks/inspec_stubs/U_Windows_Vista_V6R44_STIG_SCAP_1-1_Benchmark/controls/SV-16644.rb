control 'SV-16644' do
  title 'Power Mgmt – Password Wake on Battery'
  desc 'This check verifies that the user is prompted for a password on resume from sleep (on battery).'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Power Management -> Sleep Settings “Require a Password When a Computer Wakes (On Battery)” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15705'
  tag rid: 'SV-16644r1_rule'
  tag gtitle: 'Power Mgmt – Password Wake on Battery'
  tag fix_id: 'F-15597r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002038']
  tag nist: ['IA-11']
end
