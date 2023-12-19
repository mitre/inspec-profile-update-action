control 'SV-26665' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed. The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'check', 'Check if the rpcbind process is running.
# ps -ef | grep -v grep | grep rpcbind

If the system needs the portmap service to operate, this is not applicable. 

If a process is listed and not required, this is a finding.'
  desc 'fix', 'Stop and disable the rpcbind service, then verify it has not been
restarted.
# kill rpcbind
# chmod 0000 /usr/sbin/rpcbind   
# ps -ef | grep -v grep | grep rpcbind'
  impact 0.5
  ref 'DPMS Target HP-UX 11.31'
  tag check_id: 'C-36534r2_chk'
  tag severity: 'medium'
  tag gid: 'V-22429'
  tag rid: 'SV-26665r1_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'GEN003810'
  tag fix_id: 'F-31898r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001336']
  tag nist: ['AT-4 b']
end
