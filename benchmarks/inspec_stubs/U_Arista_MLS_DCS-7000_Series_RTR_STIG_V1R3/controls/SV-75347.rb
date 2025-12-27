control 'SV-75347' do
  title 'The Arista Multilayer Switch must disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap, while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network has documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', %q(If IPv4 or IPv6 multicast routing is enabled, verify all interfaces enabled for PIM are documented in the network's multicast topology diagram. Review the router configuration via the "show running-config" command to determine if multicast routing is enabled and which interfaces are enabled for PIM, identified via the "ip pim sparse-mode" statement in the interface configuration. Alternatively, from the interface configuration mode, enter "show active all" and verify that the statement "no ip pim sparse-mode" is present, if PIM is not required for the active interface.

If an interface is not required to support multicast routing and it is enabled, this is a finding.)
  desc 'fix', %q(Document all enabled interfaces for PIM in the network's multicast topology diagram. Disable support for PIM on interfaces that are not required to support it.

Interfaces have PIM disabled by default. To disable PIM from an interface active in a multi-cast network, enter "no pim sparse-mode" in the interface configuration mode.)
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61837r1_chk'
  tag severity: 'medium'
  tag gid: 'V-60889'
  tag rid: 'SV-75347r1_rule'
  tag stig_id: 'AMLS-L3-000110'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-66601r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
