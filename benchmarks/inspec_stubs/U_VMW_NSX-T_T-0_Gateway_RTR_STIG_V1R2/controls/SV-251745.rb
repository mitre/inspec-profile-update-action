control 'SV-251745' do
  title 'The NSX-T Tier-0 Gateway must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby know which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', 'From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway, expand the Tier-0 Gateway >> Interfaces, and click on the number of interfaces present to open the interfaces dialog.

Expand each interface that is not required to support multicast routing, then expand "Multicast" and verify PIM is disabled.

If PIM is enabled on any interfaces that are not supporting multicast routing, this is a finding.'
  desc 'fix', 'Disable multicast PIM routing on interfaces that are not required to support multicast by doing the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand "Interfaces", click on the number of interfaces present to open the interfaces dialog, and then select "Edit" on the target interface.

Expand "Multicast", change PIM to "disabled", and then click "Save".'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55182r810117_chk'
  tag severity: 'medium'
  tag gid: 'V-251745'
  tag rid: 'SV-251745r810119_rule'
  tag stig_id: 'T0RT-3X-000013'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-55136r810118_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
