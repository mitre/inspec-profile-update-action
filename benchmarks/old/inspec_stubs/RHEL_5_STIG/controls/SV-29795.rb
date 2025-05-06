control 'SV-29795' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'fix', 'Configure the system to not accept source-routed IPv4 packets.
Edit /etc/sysctl.conf and add a setting for "net.ipv4.conf.all.accept_source_route=0" and "net.ipv4.conf.default.accept_source_route=0". 

Reload the sysctls.
Procedure:
# sysctl -p'
  impact 0.5
  ref 'DPMS Target Red Hat 5'
  tag severity: 'medium'
  tag gid: 'V-12002'
  tag rid: 'SV-29795r1_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'GEN003600'
  tag fix_id: 'F-31612r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
