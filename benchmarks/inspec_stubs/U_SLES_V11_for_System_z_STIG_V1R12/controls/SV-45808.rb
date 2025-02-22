control 'SV-45808' do
  title 'The rexecd service must not be installed.'
  desc 'The rexecd process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
  desc 'check', 'Check if the rsh-server package is installed.

Procedure:
# rpm -qa | grep rsh-server

If a package is found, this is a finding.'
  desc 'fix', 'Remove the rsh-server package.

Procedure:
# rpm -e rsh-server  
# SuSEconfig'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43129r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22434'
  tag rid: 'SV-45808r1_rule'
  tag stig_id: 'GEN003845'
  tag gtitle: 'GEN003845'
  tag fix_id: 'F-39198r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
