control 'SV-45806' do
  title 'The rlogind service must not be installed.'
  desc 'The rlogind process provides a typically unencrypted, host-authenticated remote access service.  SSH should be used in place of this service.'
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
  tag check_id: 'C-43127r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22433'
  tag rid: 'SV-45806r1_rule'
  tag stig_id: 'GEN003835'
  tag gtitle: 'GEN003835'
  tag fix_id: 'F-39196r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
