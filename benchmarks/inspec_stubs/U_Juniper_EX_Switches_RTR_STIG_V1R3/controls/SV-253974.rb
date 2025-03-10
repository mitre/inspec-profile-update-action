control 'SV-253974' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for Bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.

The list of Bogon addresses can change, based upon new address range assignments, and must be reviewed to ensure filters remain current.'
  desc 'check', 'Review the BGP router configuration to verify that it will reject routes of any currently defined Bogon prefixes.

Example route-filter-list of Bogon addresses with corresponding policy-statement referencing the list:
[edit policy-options]
route-filter-list bogon {
    /* This host on this network */
    0.0.0.0/8 orlonger;
    /* CGN Addresses */
    100.64.0.0/10 orlonger;
    /* Loopback */
    127.0.0.0/8 orlonger;
    /* IPv4 link-local or APIPA */
    169.254.0.0/16 orlonger;
    /* IETF Protocol Assignments (/24) and DS-Lite (/29) */
    192.0.0.0/24 orlonger;
    /* IPv4 documentation addresses: TEST-NET-1 */
    192.0.2.0/24 orlonger;
    /* 6to4 Relay Anycast descr in RFC3068 */
    192.88.99.0/24 orlonger;
    /* Benchmark testing descr in RFC2544 */
    198.18.0.0/15 orlonger;
    /* IPv4 documentation addresses: TEST-NET-2 */
    198.51.100.0/24 orlonger;
    /* IPv4 documentation addresses: TEST-NET-3 */
    203.0.113.0/24 orlonger;
    /* Multicast */
    224.0.0.0/24 orlonger;
    /* Reserved */
    240.0.0.0/4 orlonger;
    /* RFC1918 Addresses */
    10.0.0.0/8 orlonger;
    172.16.0.0/12 orlonger;
    192.168.0.0/16 orlonger;
    <add additional routes as needed>
}
route-filter-list bogon-ipv6 {
    /* Includes unspecified (::/128) and loopback (::1/128) */
    ::/8 orlonger;
    /* IPv4-mapped */
    ::ffff:0:0/96 orlonger;
    /* IPv4 Compatible */
    ::/96 orlonger;
    /* 6Bone */
    3ffe::/16 orlonger;
    /* IPv4-IPv6 Translate */
    64:ff9b::/96 orlonger;
    /* Reserved - 100::/8 includes Discard-Only (100::/64) */
    100::/8 orlonger;
    200::/7 orlonger;
    400::/6 orlonger;
    800::/5 orlonger;
    1000::/4 orlonger;
    4000::/3 orlonger;
    6000::/3 orlonger;
    8000::/3 orlonger;
    a000::/3 orlonger;
    c000::/3 orlonger;
    e000::/4 orlonger;
    f000::/5 orlonger;
    f800::/6 orlonger;
    fe00::/9 orlonger;
    /* IETF Protocol Assignments */
    2001::/23 orlonger;
    /* TEREDO */
    2001::/32 orlonger;
    /* Benchmarking */
    2001:2::/48 orlonger;
    /* Documentation */
    2001:db8::/32 orlonger;
    /* ORCHID */
    2001:10::/28 orlonger;
    /* 6to4 */
    2002::/16 orlonger;
    /* Unique-Local */
    fc00::/7 orlonger;
    /* Linked-Scoped Unicast */
    fe80::/10 orlonger;
    /* Site local (deprecated) - now reserved */
    fec0::/10 orlonger;
    /* Multicast */
    ff00::/8 orlonger;
    <add additional routes as needed>
}
Note: The comments (/* comment */) are annotations used to easily identify each list item. Annotations are not required. To add annotations, navigate to the appropriate hierarchy level ("edit policy-options route-filter-list <list name>" in this example) and use the "annotate" command (annotate <list item> "desired comment").

policy-statement bgp-discard {
    term 1 {
        from {
            route-filter-list bogon;
            route-filter-list bogon-ipv6;
        }
        then reject;
    }
    <add additional terms as needed>
}
Note: Using a route-filter-list permits list reuse as well as easing management because the policy-statement only need reference the list once. Other terms within the same policy-statement can be added without affecting the Bogon list.

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

If the router is not configured to reject inbound route advertisements for any Bogon prefixes, this is a finding.'
  desc 'fix', 'Ensure all eBGP routers are configured to reject inbound route advertisements for any currently defined Bogon prefixes.

set policy-options route-filter-list bogon 0.0.0.0/8 orlonger
set policy-options route-filter-list bogon 10.0.0.0/8 orlonger
set policy-options route-filter-list bogon 100.64.0.0/10 orlonger
set policy-options route-filter-list bogon 127.0.0.0/8 orlonger
set policy-options route-filter-list bogon 169.254.0.0/16 orlonger
set policy-options route-filter-list bogon 172.16.0.0/12 orlonger
set policy-options route-filter-list bogon 192.0.0.0/24 orlonger
set policy-options route-filter-list bogon 192.0.2.0/24 orlonger
set policy-options route-filter-list bogon 192.168.0.0/16 orlonger
set policy-options route-filter-list bogon 198.18.0.0/15 orlonger
set policy-options route-filter-list bogon 198.51.100.0/24 orlonger
set policy-options route-filter-list bogon 203.0.113.0/24 orlonger
set policy-options route-filter-list bogon 224.0.0.0/4 orlonger
set policy-options route-filter-list bogon 240.0.0.0/4 orlonger

set policy-options route-filter-list bogon-ipv6 ::/128 exact
set policy-options route-filter-list bogon-ipv6 ::1/128 exact
set policy-options route-filter-list bogon-ipv6 ::ffff:0:0/96 orlonger
set policy-options route-filter-list bogon-ipv6 ::/96 orlonger
set policy-options route-filter-list bogon-ipv6 100::/64 orlonger
set policy-options route-filter-list bogon-ipv6 2001:10::/28 orlonger
set policy-options route-filter-list bogon-ipv6 2001:db8::/32 orlonger
set policy-options route-filter-list bogon-ipv6 fc00::/7 orlonger
set policy-options route-filter-list bogon-ipv6 fe80::/10 orlonger
set policy-options route-filter-list bogon-ipv6 fec0::/10 orlonger
set policy-options route-filter-list bogon-ipv6 ff00::/8 orlonger

set policy-options policy-statement bgp-discard term 1 from route-filter-list bogon
set policy-options policy-statement bgp-discard term 1 from route-filter-list bogon-ipv6
set policy-options policy-statement bgp-discard term 1 then reject

set protocols bgp group eBGP import bgp-discard
set protocols bgp group eBGP neighbor 192.0.2.2 import bgp-discard
set protocols bgp import bgp-discard'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57426r843953_chk'
  tag severity: 'medium'
  tag gid: 'V-253974'
  tag rid: 'SV-253974r843955_rule'
  tag stig_id: 'JUEX-RT-000020'
  tag gtitle: 'SRG-NET-000018-RTR-000002'
  tag fix_id: 'F-57377r843954_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
