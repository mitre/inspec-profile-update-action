control 'SV-253977' do
  title 'The Juniper BGP router must be configured to reject outbound route advertisements for any prefixes that do not belong to any customers or the local autonomous system (AS).'
  desc 'Advertisement of routes by an AS for networks that do not belong to any of its customers pulls traffic away from the authorized network. This causes a denial of service (DoS) on the network that allocated the block of addresses and may cause a DoS on the network that is inadvertently advertising it as the originator. It is also possible that a misconfigured or compromised router within the GIG IP core could redistribute IGP routes into BGP, thereby leaking internal routes.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the BGP router configuration to verify there is a filter defined to only advertise routes for prefixes belonging to any customer or the local AS.

Example route-filter-list of customer addresses with corresponding policy-statement referencing the list:
[edit policy-options]
route-filter-list customer1-routes {
    <customer route 1/mask> exact;
    <customer route 2/mask> exact;
}
route-filter-list customer1-routes-ipv6 {
    <customer route 1/prefix> exact;
    <customer route 2/prefix> exact;
}
<additional route-filter-lists for other customers>
policy-statement bgp-advertise-cust-routes {
    term 1 {
        from {
            route-filter-list customer1-routes;
            route-filter-list customer1-routes-ipv6;
        }
        then accept;
    }
    <additional terms for other customers>
    term default {
        then reject;
    }
}
Note: The example shows using route-filter-lists to ease management. The policy-statement also supports the route directly in the match condition. For example, "route-filter <customer route 1/mask> exact" (in place of route-filter-list customer-routes).

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements.

Verify the eBGP export statement prevents Junos from exporting routes from the route table into BGP. Junos accepts export statements at three hierarchy levels: Global protocol, group, and neighbor (peer). Global is the most general, followed by group, and neighbor is the most restrictive. Junos applies only the most restrictive policy so if a policy is configured at the protocol, group, and neighbor level, only the neighbor policy is applied.
[edit protocols bgp]
group eBGP {
    <other group configuration>
    export bgp-advertise-cust-routes;
    neighbor <address> {
        <other neighbor configuration>
        export bgp-advertise-cust-routes;
    }
}
export bgp-advertise-cust-routes;
<other BGP configuration>

If the router is not configured to reject outbound route advertisements that do not belong to any customers or the local AS, this is a finding.'
  desc 'fix', 'Configure all eBGP routers to filter outbound route advertisements for prefixes that are not allocated to or belong to any customer or the local AS.

set policy-options route-filter-list customer1-routes <customer route 1/mask> exact
set policy-options route-filter-list customer1-routes <customer route 2/mask> exact
set policy-options route-filter-list customer1-routes-ipv6 <customer route 1/prefix> exact
set policy-options route-filter-list customer1-routes-ipv6 <customer route 2/prefix> exact
<additional route-filter-list for other customers>

set policy-options policy-statement bgp-advertise-cust-routes term 1 from route-filter-list customer1-routes
set policy-options policy-statement bgp-advertise-cust-routes term 1 from route-filter-list customer1-routes-ipv6
set policy-options policy-statement bgp-advertise-cust-routes term 1 then accept
<additional terms for other customers>
set policy-options policy-statement bgp-advertise-cust-routes term default then reject

set protocols bgp group eBGP export bgp-advertise-cust-routes
set protocols bgp group eBGP neighbor <address> export bgp-advertise-cust-routes
set protocols bgp export bgp-advertise-cust-routes'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57429r843962_chk'
  tag severity: 'medium'
  tag gid: 'V-253977'
  tag rid: 'SV-253977r843964_rule'
  tag stig_id: 'JUEX-RT-000050'
  tag gtitle: 'SRG-NET-000018-RTR-000005'
  tag fix_id: 'F-57380r843963_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
