control 'SV-16648' do
  title 'Game Explorer Information Downloads'
  desc 'This check verifies that game information is not downloaded from Windows Metadata Services.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Game Explorer “Turn off downloading of game information” to “Enabled”.'
  impact 0.3
  ref 'DPMS Target Windows Vista'
  tag severity: 'low'
  tag gid: 'V-15709'
  tag rid: 'SV-16648r1_rule'
  tag gtitle: 'Game Explorer Information Downloads'
  tag fix_id: 'F-15601r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
