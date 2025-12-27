control 'SV-16583' do
  title 'Windows Peer to Peer Networking'
  desc 'This check verifies Microsoft Peer-to-Peer Networking Service is turned off.'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Network -> Microsoft Peer-to-Peer Networking Services “Turn Off Microsoft Peer-to-Peer Networking Services” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Windows XP'
  tag severity: 'medium'
  tag gid: 'V-15666'
  tag rid: 'SV-16583r1_rule'
  tag gtitle: 'Windows Peer to Peer Networking'
  tag fix_id: 'F-15530r1_fix'
  tag 'documentable'
  tag third_party_tools: 'HK'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
end
