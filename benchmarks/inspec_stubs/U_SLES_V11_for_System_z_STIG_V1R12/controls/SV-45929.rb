control 'SV-45929' do
  title 'The system must use an access control program.'
  desc 'Access control programs (such as TCP_WRAPPERS) provide the ability to enhance system security posture.'
  desc 'check', 'The tcp_wrappers package is provided with the SLES mainframe distribution. Other access control programs may be available but will need to be checked manually. 

Determine if tcp_wrappers (i.e. TCPd) is installed.
# rpm -qa | grep tcpd
If no package is listed, this is a finding.'
  desc 'fix', 'Install and configure the tcp_wrappers(i.e. tcpd) package.'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43233r1_chk'
  tag severity: 'medium'
  tag gid: 'V-940'
  tag rid: 'SV-45929r1_rule'
  tag stig_id: 'GEN006580'
  tag gtitle: 'GEN006580'
  tag fix_id: 'F-39305r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
