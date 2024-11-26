control 'SV-38827' do
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures. This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', '# /usr/sbin/no -o ip6srcrouteforward
If the value returned is not 0, this is a finding.'
  desc 'fix', 'Configure the system so it does not forward IPv6 source-routed packets.  
# /usr/sbin/no -p -o ip6srcrouteforward=0'
  impact 0.5
  ref 'DPMS Target AIX 6.1'
  tag check_id: 'C-37079r1_chk'
  tag severity: 'medium'
  tag gid: 'V-22553'
  tag rid: 'SV-38827r1_rule'
  tag stig_id: 'GEN007920'
  tag gtitle: 'GEN007920'
  tag fix_id: 'F-32350r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001551']
  tag nist: ['AC-4']
end
