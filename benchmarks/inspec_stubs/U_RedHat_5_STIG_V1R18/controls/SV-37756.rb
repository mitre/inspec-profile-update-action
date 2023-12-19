control 'SV-37756' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', 'The tcp_wrappers package is provided with the RHEL distribution. Other access control programs may be available but will need to be checked manually. 

Determine if tcp_wrappers is installed.
# rpm -qa | grep tcp_wrappers
If no package is listed, this is a finding.'
  desc 'fix', 'Install and configure the tcp_wrappers package.'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag check_id: 'C-36953r1_chk'
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
