control 'SV-217082' do
  title 'The Juniper multicast router must be configured to disable Protocol Independent Multicast (PIM) on all interfaces that are not required to support multicast routing.'
  desc %q(If multicast traffic is forwarded beyond the intended boundary, it is possible that it can be intercepted by unauthorized or unintended personnel. Limiting where, within the network, a given multicast group's data is permitted to flow is an important first step in improving multicast security. 

A scope zone is an instance of a connected region of a given scope. Zones of the same scope cannot overlap while zones of a smaller scope will fit completely within a zone of a larger scope. For example, Admin-local scope is smaller than Site-local scope, so the administratively configured boundary fits within the bounds of a site. According to RFC 4007 IPv6 Scoped Address Architecture (section 5), scope zones are also required to be "convex from a routing perspective"; that is, packets routed within a zone must not pass through any links that are outside of the zone. This requirement forces each zone to be one contiguous island rather than a series of separate islands. 

As stated in the DoD IPv6 IA Guidance for MO3, "One should be able to identify all interfaces of a zone by drawing a closed loop on their network diagram, engulfing some routers and passing through some routers to include only some of their interfaces." Therefore, it is imperative that the network engineers have documented their multicast topology and thereby knows which interfaces are enabled for multicast. Once this is done, the zones can be scoped as required.)
  desc 'check', "Review the network's multicast topology diagram.

Review the router configuration to verify that only the PIM interfaces as shown in the multicast topology diagram are enabled for PIM.

protocols {
    …
    …
    …
    pim {
        interface ge-1/0/1.0 {
            mode sparse;
        }
        interface ge-1/1/1.0 {
            mode sparse;
        }
        interface ge-2/1/0.0 {
            mode sparse;
        }
        interface ge-2/1/1.0 {
            mode sparse;
        }
    }

If an interface is not required to support multicast routing and it is enabled, this is a finding."
  desc 'fix', "Document all enabled interfaces for PIM in the network's multicast topology diagram. Disable support for PIM on interfaces that are not required to support it.

[edit protocols pim]
delete interface ge-2/1/1.0"
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18311r297114_chk'
  tag severity: 'medium'
  tag gid: 'V-217082'
  tag rid: 'SV-217082r604135_rule'
  tag stig_id: 'JUNI-RT-000780'
  tag gtitle: 'SRG-NET-000019-RTR-000003'
  tag fix_id: 'F-18309r297115_fix'
  tag 'documentable'
  tag legacy: ['SV-101157', 'V-90947']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
