control 'SV-216294' do
  title 'The rpcbind service must be configured for local only services unless organizationally defined.'
  desc 'The portmap and rpcbind services increase the attack surface of the system and should only be used when needed. The portmap or rpcbind services are used by a variety of services using remote procedure calls (RPCs).  The organization may define and document the limited use of services (for example NFS) that may use these services with approval from their Authorizing Official.'
  desc 'check', 'Check the status of the rpcbind service local_only property.
# svcprop -p config/local_only network/rpc/bind

If the state is not "true", this is a finding, unless it is required for system operations, then this is not a finding.'
  desc 'fix', 'The Service Management profile is required.

If services such as portmap or rpcbind are required for system operations, the operator must document the services used and obtain approval from their Authorizing Official. They should also document the method(s) of blocking all other remote accesses through tools like a firewall or tcp_wrappers.
Otherwise, configure the rpc/bind service for local only access. 

# svccfg -s network/rpc/bind setprop config/local_only=true'
  impact 0.5
  ref 'DPMS Target Solaris 11 SPARC'
  tag check_id: 'C-17530r370970_chk'
  tag severity: 'medium'
  tag gid: 'V-216294'
  tag rid: 'SV-216294r603267_rule'
  tag stig_id: 'SOL-11.1-020170'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-17528r370971_fix'
  tag 'documentable'
  tag legacy: ['SV-60791', 'V-47919']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
