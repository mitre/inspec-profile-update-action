control 'SV-37756' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'fix', 'Install and configure the tcp_wrappers package.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-940'
  tag rid: 'SV-37756r1_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'GEN006580'
  tag fix_id: 'F-32218r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'EBRU-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
