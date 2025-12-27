control 'SV-253975' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping, being black holed, or at a minimum using a nonoptimized path.'
  desc 'check', 'Review the BGP router configuration to verify that it will reject routes belonging to the local AS.

Example route-filter-list of local AS addresses with corresponding policy-statement referencing the list. Verify the routes are appropriate for the target environment.
[edit policy-options]
route-filter-list local-routes {
    192.0.2.0/24 orlonger;
    192.0.3.0/24 orlonger;
}
route-filter-list local-routes-ipv6 {
    2001:db8:2::/64 orlonger;
    2001:db8:3::/64 orlonger;
}
policy-statement bgp-discard {
    term 1 {
        from {
            route-filter-list bogon;
            route-filter-list bogon-ipv6;
        }
        then reject;
    }
    term 2 {
        from {
            route-filter-list local-routes;
            route-filter-list local-routes-ipv6;
        }
        then reject;
    }
    term 3 {
        from protocol [ ospf direct ];
        then reject;
    }
}
The example shows using route-filter-lists to ease management. The policy-statement also supports the route directly in the match condition. For example, "route-filter 192.0.2.0/24 orlonger" (in place of route-filter-list local-routes).

Note: To reject routes learned via OSPF or directly-connected routes, include a term with a protocol (OSPF and directly-connected routes shown). The policy-statement includes the Bogon term to demonstrate adding terms to a policy without affecting existing terms.

The prefix filter must be referenced inbound on the appropriate BGP neighbor statements.

Verify the eBGP import statement prevents Junos from importing routes into the route table. Junos accepts import statements at three hierarchy levels: Global protocol, group, and neighbor (peer). Global is the most general, followed by group, and neighbor is the most restrictive. Junos applies only the most restrictive policy so if a policy is configured at the protocol, group, and neighbor level, only the neighbor policy is applied.
[edit protocols bgp]
group eBGP {
    <other group configuration>
    import bgp-discard;
    neighbor 192.0.2.2 {
        <other neighbor configuration>
        import bgp-discard;
    }
}
import bgp-discard;
<other BGP configuration>

If the router is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Ensure all eBGP routers are configured to reject inbound route advertisements for any prefixes belonging to the local AS.

set policy-options route-filter-list local-routes 192.0.2.0/24 orlonger
set policy-options route-filter-list local-routes 192.0.3.0/24 orlonger
set policy-options route-filter-list local-routes-ipv6 2001:db8:2::/64 orlonger
set policy-options route-filter-list local-routes-ipv6 2001:db8:3::/64 orlonger

set policy-options policy-statement bgp-discard term 1 from route-filter-list bogon
set policy-options policy-statement bgp-discard term 1 from route-filter-list bogon-ipv6
set policy-options policy-statement bgp-discard term 1 then reject
set policy-options policy-statement bgp-discard term 2 from route-filter-list local-routes
set policy-options policy-statement bgp-discard term 2 from route-filter-list local-routes-ipv6
set policy-options policy-statement bgp-discard term 2 then reject
set policy-options policy-statement bgp-discard term 3 from protocol ospf
set policy-options policy-statement bgp-discard term 3 from protocol direct
set policy-options policy-statement bgp-discard term 3 then reject

set protocols bgp group eBGP import bgp-discard
set protocols bgp group eBGP neighbor 192.0.2.2 import bgp-discard
set protocols bgp import bgp-discard'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57427r843956_chk'
  tag severity: 'medium'
  tag gid: 'V-253975'
  tag rid: 'SV-253975r843958_rule'
  tag stig_id: 'JUEX-RT-000030'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-57378r843957_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
