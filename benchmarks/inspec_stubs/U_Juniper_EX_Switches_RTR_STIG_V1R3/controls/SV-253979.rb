control 'SV-253979' do
  title 'The Juniper router configured for Multicast Source Discovery Protocol (MSDP) must filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the router configuration to determine if there is an import policy to block source-active multicast advertisements for any undesirable multicast groups, as well as any (S, G) states with undesirable source addresses. 

Verify that an inbound source-active filter is bound to each MSDP peer.

[edit protocols msdp]
peer <address> {
    import source-active-filter;
}

Review the policy-statement referenced by the source-active filter to verify that undesirable multicast groups, auto-RP, single source multicast (SSM) groups, and advertisements from undesirable sources are blocked.

[edit policy-options]
policy-statement source-active-filter {
    term unauth-groups {
        from {
            route-filter 224.0.1.2/32 exact;
            route-filter 224.0.2.2/32 exact;
        }
        then reject;
    }
    term unauth-sources {
        from {
            source-address-filter 10.0.0.0/8 orlonger;
            source-address-filter 127.0.0.0/8 orlonger;
        }
        then reject;
    }
}

If the router is not configured with an import policy to block undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP router to implement an import policy to block multicast advertisements for undesirable multicast groups and sources.

set protocols msdp peer <address> import source-active-filter

set policy-options policy-statement source-active-filter term unauth-groups from route-filter 224.0.1.2/32 exact
set policy-options policy-statement source-active-filter term unauth-groups from route-filter 224.0.2.2/32 exact
set policy-options policy-statement source-active-filter term unauth-groups then reject
set policy-options policy-statement source-active-filter term unauth-sources from source-address-filter 10.0.0.0/8 orlonger
set policy-options policy-statement source-active-filter term unauth-sources from source-address-filter 127.0.0.0/8 orlonger
set policy-options policy-statement source-active-filter term unauth-sources then reject'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57431r843968_chk'
  tag severity: 'low'
  tag gid: 'V-253979'
  tag rid: 'SV-253979r843970_rule'
  tag stig_id: 'JUEX-RT-000070'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-57382r843969_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
