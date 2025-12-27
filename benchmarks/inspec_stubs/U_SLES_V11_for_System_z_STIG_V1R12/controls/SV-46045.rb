control 'SV-46045' do
  title 'Automated file system mounting tools must not be enabled unless needed.'
  desc 'Automated file system mounting tools may provide unprivileged users with the ability to access local media and network shares.  If this access is not necessary for the system’s operation, it must be disabled to reduce the risk of unauthorized access to these resources.'
  desc 'check', 'Check if the autofs service is running.
# rcautofs status
     OR
# service autofs status
If the service is running, this is a finding.'
  desc 'fix', 'Stop and disable the autofs service.
# rcautofs stop
     OR
# service autofs stop
# insserv –r autofs
     OR
# chkconfig autofs off'
  impact 0.3
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43316r2_chk'
  tag severity: 'low'
  tag gid: 'V-22577'
  tag rid: 'SV-46045r1_rule'
  tag stig_id: 'GEN008440'
  tag gtitle: 'GEN008440'
  tag fix_id: 'F-39404r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
