control 'SV-253985' do
  title 'The Juniper router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby know which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', %q(If IPv4 or IPv6 multicast routing is enabled, verify all interfaces enabled for PIM are documented in the network's multicast topology diagram.

Review the router configuration to determine if multicast routing is enabled and which interfaces are enabled for PIM.

By default, PIM is not enabled on any interface. If not a PIM router, verify there is no PIM stanza at [edit protocols], PIM is disabled globally and/or for all interfaces, or that the stanza is inactive.
[edit protocols]
inactive: pim { << Stanza is removed or marked inactive
    disable; << If stanza is present and not inactive, verify globally disabled
    interface all { << If stanza is present, not inactive, and not globally disabled, disable for all interfaces
        disable;
    }
}

For PIM routers, verify only the required interfaces are configured. For example, the following configuration enables PIM on a specific interface and disables PIM for all others.
[edit protocols]
pim {
    interface <name>.<logical unit>;
    interface all {
        disable;
    }
}

Note: More specific interface configuration statements are preferred. In the example, the interface configuration is more specific than interface "all", so PIM is enabled only on that interface.

If an interface is not required to support multicast routing and it is enabled, this is a finding.)
  desc 'fix', "Document all enabled interfaces for PIM in the network's multicast topology diagram. Disable support for PIM on interfaces that are not required to support it.

For non-PIM routers, verify there is no [edit protocols pim] stanza. If the stanza is present, delete or deactivate it.
delete protocols pim
deactivate protocols pim

To disable PIM globally or for all interfaces.
set protocols pim disable
set protocols pim interface all disable

For PIM routers verify only the required interfaces are configured and all others are disabled:
set protocols pim interface <name>.<logical unit>
set protocols pim interface all disable"
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57437r843986_chk'
  tag severity: 'medium'
  tag gid: 'V-253985'
  tag rid: 'SV-253985r843988_rule'
  tag stig_id: 'JUEX-RT-000130'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-57388r843987_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
