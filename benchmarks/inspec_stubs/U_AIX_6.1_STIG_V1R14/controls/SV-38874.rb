control 'SV-38874' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'If the portmap service is required for system operations, this is not a finding.

Determine if the portmap service is running.
#ps -ef|grep portmap
If portmap is running, this is a finding.'
  desc 'fix', 'Disable the portmap service from auto starting by commenting out portmap from /etc/rc.tcpip.

# vi /etc/rc.tcpip

Shutdown the portmap service.
# ps -ef | grep portmap
# kill <pid of portmap>'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37882r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22429'
  tag rid: 'SV-38874r1_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'GEN003810'
  tag fix_id: 'F-31833r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001336']
  tag nist: ['AT-4 b']
end
