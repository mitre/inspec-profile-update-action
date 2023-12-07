control 'SV-26662' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using Remote Procedure Calls (RPCs).'
  desc 'fix', 'Shutdown and disable the portmap service.
# service portmap stop; chkconfig portmap off'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-22429'
  tag rid: 'SV-26662r1_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'GEN003810'
  tag fix_id: 'F-23904r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001436']
  tag nist: ['AC-17 (8)']
end
