control 'SV-26666' do
  title 'The portmap or rpcbind service must not be installed unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'fix', 'Remove the portmap package.
# rpm -e portmap
or 
# yum remove portmap'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22430'
  tag rid: 'SV-26666r1_rule'
  tag stig_id: 'GEN003815'
  tag gtitle: 'GEN003815'
  tag fix_id: 'F-23908r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000305']
  tag nist: ['CM-7 (2)']
end
