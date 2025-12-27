control 'SV-45785' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'Check the status of the portmap and/or rpcbind service.
# rcportmap status
# rcrpcbind status

If the service is running, this is a finding.'
  desc 'fix', 'Shutdown and disable the portmap and/or rpcbind service.
# rcportmap stop; insserv –r portmap
# rcrpcbind stop; insserv –r rpcbind'
  impact 0.5
  ref 'DPMS Target SuSe 11.x s390x/zLinux'
  tag check_id: 'C-43122r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22429'
  tag rid: 'SV-45785r1_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'GEN003810'
  tag fix_id: 'F-39179r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001336']
  tag nist: ['AT-4 b']
end
