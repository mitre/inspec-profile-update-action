control 'SV-255998' do
  title 'The Arista multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DOD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', %q(If IPv4 or IPv6 multicast routing is enabled on the Arista router, verify all interfaces enabled for PIM are documented in the network's multicast topology diagram.

Review the Arista router configuration to determine which interfaces are enabled for PIM, identified via the "pim ipv4 sparse-mode" for ipv4 and "pim ipv6 sparse-mode" for ipv6 statement in the interface configuration, and compare to the topology.

sh run | sec pim

interface Ethernet3
   pim ipv4 sparse-mode
interface Ethernet8
   pim ipv4 sparse-mode
   pim ipv6 sparse-mode
interface Ethernet9
   pim ipv4 sparse-mode
   pim ipv6 sparse-mode
interface Vlan8
   pim ipv4 sparse-mode 

If an interface is not required to support multicast routing and it is enabled, this is a finding.)
  desc 'fix', %q(Document all enabled interfaces for PIM in the network's multicast topology diagram. Disable support for PIM on interfaces that are not required to support it.

Step 1: Configure the router in global configuration mode to support multicast routing.

router(config)#router multicast 
router(config-router-multicast)#ipv4
router(config-router-multicast-ipv4)#routing
router(config-router-multicast-ipv4)#exit
router(config-router-multicast)#exit

Step 2: Enable PIM on interfaces required to support multicast.

Interfaces have PIM disabled by default. To enable PIM from an interface active in a multicast network, enter "pim sparse-mode" in the interface configuration mode.

router(config)#interface Ethernet1
router(config-if-Et1)#pim ipv4 sparse-mode
router(config-if-Et1)#pim ipv6 sparse-mode

Step 3: Disable support for PIM on interfaces that are not required to support it.

router(config)#interface Ethernet2
router(config-if-Et2)#no pim ipv4 sparse-mode
router(config-if-Et2)#no pim ipv6 sparse-mode)
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59674r882334_chk'
  tag severity: 'medium'
  tag gid: 'V-255998'
  tag rid: 'SV-255998r882336_rule'
  tag stig_id: 'ARST-RT-000120'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-59617r882335_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
