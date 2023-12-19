control 'SV-253980' do
  title 'The Juniper router configured for Multicast Source Discovery Protocol (MSDP) must filter source-active multicast advertisements to external MSDP peers to avoid global visibility of local-only multicast sources and groups.'
  desc 'To avoid global visibility of local information, there are a number of source-group (S, G) states in a PIM-SM domain that must not be leaked to another domain, such as multicast sources with private address, administratively scoped multicast addresses, and the auto-RP groups (224.0.1.39 and 224.0.1.40).

Allowing a multicast distribution tree, local to the core, to extend beyond its boundary could enable local multicast traffic to leak into other autonomous systems and customer networks.'
  desc 'check', 'Review the router configuration to determine if there is export policy to block local source-active multicast advertisements.

Verify that an outbound source-active filter is bound to each MSDP peer.

[edit protocols msdp]
peer <address> {
    export source-active-filter;
}

Review the policy-statement referenced by the source-active filters and verify that MSDP source-active messages being sent to MSDP peers do not leak advertisements that are local.

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

If the router is not configured with an export policy to block local source-active multicast advertisements, this is a finding.'
  desc 'fix', 'Ensure an export policy is implemented on all MSDP routers to avoid global visibility of local multicast (S, G) states.

set protocols msdp peer <address> export source-active-filter

set policy-options policy-statement source-active-filter term unauth-groups from route-filter 224.0.1.2/32 exact
set policy-options policy-statement source-active-filter term unauth-groups from route-filter 224.0.2.2/32 exact
set policy-options policy-statement source-active-filter term unauth-groups then reject
set policy-options policy-statement source-active-filter term unauth-sources from source-address-filter 10.0.0.0/8 orlonger
set policy-options policy-statement source-active-filter term unauth-sources from source-address-filter 127.0.0.0/8 orlonger
set policy-options policy-statement source-active-filter term unauth-sources then reject'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57432r843971_chk'
  tag severity: 'low'
  tag gid: 'V-253980'
  tag rid: 'SV-253980r843973_rule'
  tag stig_id: 'JUEX-RT-000080'
  tag gtitle: 'SRG-NET-000018-RTR-000008'
  tag fix_id: 'F-57383r843972_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
