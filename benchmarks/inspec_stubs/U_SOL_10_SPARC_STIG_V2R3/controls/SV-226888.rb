control 'SV-226888' do
  title 'The system must not forward IPv4 source-routed packets.'
  desc 'Source-routed packets allow the source of the packet to suggest that routers forward the packet along a different path than configured on the router, which can be used to bypass network security measures.  This requirement applies only to the forwarding of source-routed traffic, such as when IPv4 forwarding is enabled and the system is functioning as a router.'
  desc 'check', 'Determine the type of zone that you are currently securing.
# zonename

If the zone is not the global zone, determine if any interfaces are exclusive to the zone:
# dladm show-link

If the output indicates "insufficient privileges" then this requirement is not applicable.

If the zone is the global zone or the non-global zone has exclusive interfaces verify the network settings: 

# ndd /dev/ip ip_forward_src_routed
If the returned value is not 0, this is a finding.'
  desc 'fix', 'Configure the system to not forward IPv4 source-routed packets.
Procedure:
# ndd /dev/ip ip_forward_src_routed 0

This command must also be added to a system startup script.'
  impact 0.5
  ref 'DPMS Target Solaris 10 SPARC'
  tag check_id: 'C-29050r484948_chk'
  tag severity: 'medium'
  tag gid: 'V-226888'
  tag rid: 'SV-226888r603265_rule'
  tag stig_id: 'GEN003600'
  tag gtitle: 'SRG-OS-000480'
  tag fix_id: 'F-29038r484949_fix'
  tag 'documentable'
  tag legacy: ['V-12002', 'SV-27420']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
