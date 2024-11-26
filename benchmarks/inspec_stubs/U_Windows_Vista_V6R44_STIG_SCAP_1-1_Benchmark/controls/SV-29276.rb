control 'SV-29276' do
  title 'The system is configured to allow remote desktop sharing through NetMeeting.'
  desc 'Remote desktop sharing enables several users to interact and control one desktop.  This could allow unauthorized users to control the system.  Remote desktop sharing should be disabled.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> NetMeeting “Disable remote Desktop Sharing” to “Enabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-3426'
  tag rid: 'SV-29276r1_rule'
  tag gtitle: 'NetMeeting Disable Remote Desktop Sharing'
  tag fix_id: 'F-5908r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
