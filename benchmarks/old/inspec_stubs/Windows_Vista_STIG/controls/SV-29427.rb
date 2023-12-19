control 'SV-29427' do
  title 'Windows Peer to Peer Networking'
  desc 'This check verifies Microsoft Peer-to-Peer Networking Service is turned off.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services “Turn Off Microsoft Peer-to-Peer Networking Services” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag severity: 'medium'
  tag gid: 'V-15666'
  tag rid: 'SV-29427r1_rule'
  tag gtitle: 'Windows Peer to Peer Networking'
  tag fix_id: 'F-15530r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
