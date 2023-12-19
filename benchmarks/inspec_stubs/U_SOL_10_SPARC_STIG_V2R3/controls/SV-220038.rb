control 'SV-220038' do
  title 'The portmap or rpcbind service must not be running unless needed.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed.  The portmap or rpcbind services are used by a variety of services using remote procedure calls (RPCs).'
  desc 'check', 'Check the status of the rpcbind service.

# svcs network/rpc/bind

If the service is online and is not documented as required, this is a finding.'
  desc 'fix', 'Disable the portmap service.
# svcadm disable network/rpc/bind'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-21747r485035_chk'
  tag severity: 'medium'
  tag gid: 'V-220038'
  tag rid: 'SV-220038r603265_rule'
  tag stig_id: 'GEN003810'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-21746r485036_fix'
  tag 'documentable'
  tag legacy: ['SV-26664', 'V-22429']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
