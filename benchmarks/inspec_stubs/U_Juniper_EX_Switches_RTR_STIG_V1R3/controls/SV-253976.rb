control 'SV-253976' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements from a customer edge (CE) router for prefixes that are not allocated to that customer.'
  desc 'As a best practice, a service provider should only accept customer prefixes that have been assigned to that customer and any peering autonomous systems. A multi-homed customer with BGP speaking routers connected to the internet or other external networks could be breached and used to launch a prefix deaggregation attack. Without ingress route filtering of customers, the effectiveness of such an attack could impact the entire IP core and its customers.'
  desc 'check', 'Review the BGP router configuration to verify there are filters defined to only accept routes for prefixes that belong to specific customers. 

Example route-filter-list of customer addresses with corresponding policy-statement referencing the list:
[edit policy-options]
route-filter-list customer1-routes {
    <customer route 1/mask> orlonger;
    <customer route 2/mask> orlonger;
}
route-filter-list customer1-routes-ipv6 {
    <customer route 1/prefix> orlonger;
    <customer route 1/prefix> orlonger;
}
<additional route-filter-list for other customers>
policy-statement bgp-accept-cust1-routes {
    term 1 {
        from {
            route-filter-list customer1-routes;
            route-filter-list customer1-routes-ipv6;
        }
        then accept;
    }
    term 2 {
        then reject;
    }
}
<additional policies for other customers>
Note: The example shows using route-filter-lists to ease management. The policy-statement also supports the route directly in the match condition. For example, "route-filter <customer route 1/mask> orlonger" (in place of route-filter-list customer-routes).

Verify the eBGP import statement prevents Junos from importing routes into the route table. Junos accepts import statements at three hierarchy levels: Global protocol, group, and neighbor (peer). Global is the most general, followed by group, and neighbor is the most restrictive. Junos applies only the most restrictive policy so if a policy is configured at the protocol, group, and neighbor level, only the neighbor policy is applied.
[edit protocols bgp]
group customer1 {
    <other group configuration>
    import bgp-accept-cust1-routes;
    neighbor <address> {
        <other neighbor configuration>
        import bgp-accept-cust1-routes;
    }
}
import <import policy name>;
<other BGP configuration>

If the router is not configured to reject inbound route advertisements from each CE router for prefixes that are not allocated to that customer, this is a finding.

Note: Routes to PE-CE links within a VPN are needed for troubleshooting end-to-end connectivity across the MPLS/IP backbone. Hence, these prefixes are an exception to this requirement.'
  desc 'fix', 'Configure all eBGP routers to reject inbound route advertisements from a CE router for prefixes that are not allocated to that customer.

set policy-options route-filter-list customer1-routes <customer route 1/mask> orlonger
set policy-options route-filter-list customer1-routes <customer route 2/mask> orlonger
set policy-options route-filter-list customer1-routes-ipv6 <customer route 1/prefix> orlonger
set policy-options route-filter-list customer1-routes-ipv6 <customer route 2/prefix> orlonger
<additional route-filter-list for other customers>

set policy-options policy-statement bgp-accept-cust1-routes term 1 from route-filter-list customer-routes
set policy-options policy-statement bgp-accept-cust1-routes term 1 from route-filter-list customer-routes-ipv6
set policy-options policy-statement bgp-accept-cust1-routes term 1 then accept
set policy-options policy-statement bgp-accept-cust1-routes term 2 then reject
<additional policies for other customers>

set protocols bgp group customer1 import bgp-accept-cust1-routes
set protocols bgp group customer1 neighbor <address> import bgp-accept-cust1-routes

Note: An import filter is only required at the group, or the neighbor, level but not both unless the specific neighbor requires a different import filter than the group.'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57428r843959_chk'
  tag severity: 'medium'
  tag gid: 'V-253976'
  tag rid: 'SV-253976r843961_rule'
  tag stig_id: 'JUEX-RT-000040'
  tag gtitle: 'SRG-NET-000018-RTR-000004'
  tag fix_id: 'F-57379r843960_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
