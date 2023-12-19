control 'SV-217095' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to filter received source-active multicast advertisements for any undesirable multicast groups and sources.'
  desc 'The interoperability of BGP extensions for interdomain multicast routing and MSDP enables seamless connectivity of multicast domains between autonomous systems. MP-BGP advertises the unicast prefixes of the multicast sources used by Protocol Independent Multicast (PIM) routers to perform RPF checks and build multicast distribution trees. MSDP is a mechanism used to connect multiple PIM sparse-mode domains, allowing RPs from different domains to share information about active sources. When RPs in peering multicast domains hear about active sources, they can pass on that information to their local receivers, thereby allowing multicast data to be forwarded between the domains. Configuring an import policy to block multicast advertisements for reserved, Martian, single-source multicast, and any other undesirable multicast groups, as well as any source-group (S, G) states with Bogon source addresses, would assist in avoiding unwanted multicast traffic from traversing the core.'
  desc 'check', 'Review the router configuration to determine if there is import policy to block source-active multicast advertisements for undesirable multicast groups and sources. 

policy-options {
   …
    …
    …
    }
    policy-statement SA_IMPORT {
        term BAD_GROUPS {
            from {
                route-filter 224.0.1.2/32 exact;
                route-filter 224.77.0.0/16 orlonger;
            }
            then reject;
        }
        term BAD_SOURCES {
            from {
                source-address-filter x.x.x.x /8 orlonger;
                source-address-filter x.x.x.x /8 orlonger;
 
            then accept;
        }
    }

Verify that an import source-active filter has been applied to MSDP.

protocols {
    …
    …
    …
    }
    msdp {
        import SA_IMPORT;

If the router is not configured with an import policy to block undesirable SA multicast advertisements, this is a finding.'
  desc 'fix', 'Configure the MSDP to implement an import policy to block multicast advertisements for undesirable multicast groups and sources.

Configure the source-active filter to reject undesirable multicast groups and sources as shown in the example below.

[edit policy-options]
set policy-statement SA_IMPORT term BAD_GROUPS from route-filter 224.0.1.2/32 exact
set policy-statement SA_IMPORT term BAD_GROUPS from route-filter 224.77.0.0/16 orlonger
set policy-statement SA_IMPORT term BAD_GROUPS then reject
set policy-statement SA_IMPORT term BAD_SOURCES from source-address-filter x.x.x.x/8 orlonger
set policy-statement SA_IMPORT term BAD_SOURCES from source-address-filter x.x.x.x/16 orlonger
set policy-statement SA_IMPORT term BAD_SOURCES then reject
set policy-statement SA_IMPORT term ACCEPT_OTHERS then accept

Configure the source-active filter to be an import filter.

[edit protocols msdp]
set import SA_IMPORT'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18324r297153_chk'
  tag severity: 'low'
  tag gid: 'V-217095'
  tag rid: 'SV-217095r639663_rule'
  tag stig_id: 'JUNI-RT-000910'
  tag gtitle: 'SRG-NET-000018-RTR-000007'
  tag fix_id: 'F-18322r297154_fix'
  tag 'documentable'
  tag legacy: ['SV-101183', 'V-90973']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
