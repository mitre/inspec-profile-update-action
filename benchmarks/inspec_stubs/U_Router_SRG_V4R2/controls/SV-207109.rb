control 'SV-207109' do
  title 'The multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', "If IPv4 or IPv6 multicast routing is enabled, verify all interfaces enabled for PIM are documented in the network's multicast topology diagram.

Review the router configuration to determine if multicast routing is enabled and which interfaces are enabled for PIM.

If an interface is not required to support multicast routing and it is enabled, this is a finding."
  desc 'fix', "Document all enabled interfaces for PIM in the network's multicast topology diagram. Disable support for PIM on interfaces that are not required to support it."
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7370r382172_chk'
  tag severity: 'medium'
  tag gid: 'V-207109'
  tag rid: 'SV-207109r604135_rule'
  tag stig_id: 'SRG-NET-000019-RTR-000003'
  tag gtitle: 'SRG-NET-000019'
  tag fix_id: 'F-7370r382173_fix'
  tag 'documentable'
  tag legacy: ['SV-69977', 'V-55723']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
