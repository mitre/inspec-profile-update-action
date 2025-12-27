control 'SV-80625' do
  title 'The HP FlexFabric Switch must disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network has documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', 'Review the multicast topology diagram and determine which HP FlexFabric Switch interfaces should have Protocol Independent Multicast enabled. Disable PIM on interfaces that should not have it enabled.

If PIM is enabled interfaces that are not required to support multicast routing, this is a finding.

[HP]display current-configuration interface 
interface GigabitEthernet0/1
 port link-mode route
 pim sm
 ip address 192.168.10.1 255.255.255.0
 packet-filter 3010 inbound

 [HP FlexFabric SwitchD] display pim neighbor
Total Number of Neighbors = 3
Neighbor          Interface   Uptime        Expires Dr-Priority
192.168.10.2     GE0/1     00:02:22     00:01:27 1'
  desc 'fix', 'Disable PIM on the HP FlexFabric Switch interfaces that should not have it enabled:

[HP-GigabitEthernet0/1] undo pim sm'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66781r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66135'
  tag rid: 'SV-80625r1_rule'
  tag stig_id: 'HFFS-RT-000024'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-72211r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
