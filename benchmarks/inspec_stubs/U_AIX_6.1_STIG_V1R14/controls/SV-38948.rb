control 'SV-38948' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', '# /usr/sbin/no -o ipsrcrouteforward
If the returned value is not 0, this is a finding.'
  desc 'fix', '# /usr/sbin/no -po "ipsrcrouteforward=0"'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-28608r1_chk'
  tag severity: 'medium'
  tag gid: 'V-12002'
  tag rid: 'SV-38948r1_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'GEN003600'
  tag fix_id: 'F-32490r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
