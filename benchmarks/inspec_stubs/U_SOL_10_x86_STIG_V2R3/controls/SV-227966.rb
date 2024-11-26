control 'SV-227966' do
  title 'The system must not forward IPv6 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv6 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the system is configured to not forward IPv6 source-routed packets.
# ndd /dev/ip6 ip6_forward_src_routed

If the returned value is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not forward IPv6 source-routed packets.
# ndd -set /dev/ip6 ip6_forward_src_routed 0

Also, add this command to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 X86'
  tag check_id: 'C-30128r490333_chk'
  tag severity: 'medium'
  tag gid: 'V-227966'
  tag rid: 'SV-227966r603266_rule'
  tag stig_id: 'GEN007920'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-30116r490334_fix'
  tag 'documentable'
  tag legacy: ['V-22553', 'SV-26940']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
