control 'SV-254046' do
  title 'The Juniper perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc "Bogons include IP packets on the public internet that contain addresses that are not in any range allocated or delegated by the Internet Assigned Numbers Authority (IANA) or a delegated regional Internet registry (RIR) and allowed for public internet use. Bogons also include multicast, IETF reserved, and special purpose address space as defined in RFC 6890.

Security of the internet's routing system relies on the ability to authenticate an assertion of unique control of an address block. Measures to authenticate such assertions rely on the validation the address block forms as part of an existing allocated address block, and must be a trustable and unique reference in the IANA address registries. The intended use of a Bogon address would only be for the purpose of address spoofing in denial-of-service attacks. Hence, it is imperative that IP packets with a source Bogon address are blocked at the network’s perimeter."
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Verify that the ingress filter is blocking packets with Bogon source addresses. Bogon addresses are added to prefix lists to ease management, and prefix lists are associated with firewall filters. Verify appropriate prefix lists for IPv4 and IPv6 Bogon addresses. For example:
[edit policy-options]
prefix-list bogon-addresses-ipv4 {
    /* This host on this network */
    0.0.0.0/8;
    /* CGN Addresses */
    100.64.0.0/10;
    /* Loopback */
    127.0.0.0/8;
    /* IPv4 link-local or APIPA */
    169.254.0.0/16;
    /* IETF Protocol Assignments */
    192.0.0.0/24;
    /* IPv4 documentation addresses: TEST-NET-1 */
    192.0.2.0/24;
    /* 6to4 Relay Anycast descr in RFC3068 */
    192.88.99.0/24;
    /* Benchmark testing descr in RFC2544 */
    198.18.0.0/15;
    /* IPv4 documentation addresses: TEST-NET-2 */
    198.51.100.0/24;
    /* IPv4 documentation addresses: TEST-NET-3 */
    203.0.113.0/24;
    /* Multicast */
    224.0.0.0/24;
    /* Reserved */
    240.0.0.0/4;
    /* RFC1918 Addresses */
    10.0.0.0/8;
    172.16.0.0/12;
    192.168.0.0/16;
    <add additional routes as needed>
}
route-filter-list bogon-ipv6 {
    /* Unspecified */
    ::/128;
    /* Loopback */
    ::1/128;
    /* IPv4 Compatible */
    0::/96;
    /* IPv4-mapped */
    ::ffff:0:0/96;
    /* 6Bone */
    3ffe::/16;
    /* IPv4-IPv6 Translate */
    64:ff9b::/96;
    /* Discard-Only */
    100::/64;
    /* ORCHID */
    2001:10::/28;
    /* Documentation */
    2001:db8::/32;
    /* Benchmarking */
    2001:2::/48;
    /* TEREDO */
    2001::/32;
    /* IETF Protocol Assignments */
    2001::/23;
    /* 6to4 */
    2002::/16;
    /* Unique-Local */
    fc00::/7;
    /* Site local (deprecated) - now reserved */
    fec0::/10;
    /* Multicast */
    ff00::/8;
    <add additional routes as needed>
}

Note: The comments associated with addresses is configured with the "annotate" command. Annotations will appear in the standard hierarchical configuration display but do not appear when using "display set". The annotations are not required but added to this check to show what each address represents.

Verify IPv4 and IPv6 firewall filters incorporate Bogon address restrictions.
[edit firewall]
family inet {
    filter inbound-ipv4 {
        term 1 {
            from {
                source-prefix-list bogon-ipv4;
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        <permitted traffic terms>
    }
}
family inet6 {
    filter inbound-ipv6 {
        term 1 {
            from {
                source-prefix-list bogon-ipv6;
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        <permitted traffic terms>
    }
}

Review the router configuration to verify that it is configured to block IP packets with a Bogon source address. Verify the firewall filter enforcing Bogon restrictions is applied inbound on exterior-facing interfaces. For example:
[edit interfaces]
<interface name> {
    unit <number> {
        family inet {
            filter {
                input inbound-ipv4;
            }
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                input inbound-ipv6;
            }
            address <IPv6 address>/<prefix>;
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

Reference minimum IPv4 Bogon Prefixes
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24  
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15 
198.51.100.0/24
203.0.113.0/24 
224.0.0.0/4 
240.0.0.0/4

Reference minimum IPv6 Bogon Prefixes
::/128
::1/128
0::/96
::ffff:0:0/96 
3ffe::/16 
64:ff9b::/96  
100::/64   
2001:10::/28   
2001:db8::/32   
2001:2::/48  
2001::/32  
2001::/23 
2002::/16   
fc00::/7 
fe80::/10  
fec0::/10  
ff00::/8
     
If the router is not configured to block inbound IP packets containing a Bogon source address, this is a finding.

Note: At a minimum, IP packets containing a source address from the special purpose address space as defined in RFC 6890 must be blocked. The 6Bone prefix (3ffe::/16) is also be considered a Bogon address. Perimeter routers connected to commercial ISPs for internet or other non-DoD network sources will need to be reviewed for a full Bogon list. 

The IPv4 full Bogon list contains prefixes that have been allocated to RIRs but not assigned by those RIRs. Reference the following link: http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt

The IPv6 full Bogon list contains prefixes that have not been allocated to RIRs, or those that have been allocated to RIRs but have not been assigned by those RIRs. Reference the following link: https://www.team-cymru.org/Services/Bogons/fullbogons-ipv6.txt'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone. 

Configure the router to block inbound packets with Bogon source addresses.

Example Bogon prefix lists:
set policy-options prefix-list bogon-ipv4 0.0.0.0/8
set policy-options prefix-list bogon-ipv4 10.0.0.0/8
set policy-options prefix-list bogon-ipv4 100.64.0.0/10
set policy-options prefix-list bogon-ipv4 127.0.0.0/8
set policy-options prefix-list bogon-ipv4 169.254.0.0/16
set policy-options prefix-list bogon-ipv4 172.16.0.0/12
set policy-options prefix-list bogon-ipv4 192.0.0.0/24
set policy-options prefix-list bogon-ipv4 192.0.2.0/24
set policy-options prefix-list bogon-ipv4 192.88.99.0/24
set policy-options prefix-list bogon-ipv4 192.168.0.0/16
set policy-options prefix-list bogon-ipv4 198.18.0.0/15
set policy-options prefix-list bogon-ipv4 198.51.100.0/24
set policy-options prefix-list bogon-ipv4 203.0.113.0/24
set policy-options prefix-list bogon-ipv4  224.0.0.0/24
set policy-options prefix-list bogon-ipv4 240.0.0.0/4

set policy-options prefix-list bogon-ipv6 ::/128
set policy-options prefix-list bogon-ipv6 ::1/128
set policy-options prefix-list bogon-ipv6 0::/96
set policy-options prefix-list bogon-ipv6 ::ffff:0:0/96
set policy-options prefix-list bogon-ipv6 3ffe::/16
set policy-options prefix-list bogon-ipv6 64:ff9b::/96
set policy-options prefix-list bogon-ipv6 100::/64
set policy-options prefix-list bogon-ipv6 2001:10::/28
set policy-options prefix-list bogon-ipv6 2001:db8::/32
set policy-options prefix-list bogon-ipv6 2001:2::/48
set policy-options prefix-list bogon-ipv6 2001::/32
set policy-options prefix-list bogon-ipv6 2001::/23
set policy-options prefix-list bogon-ipv6 2002::/16
set policy-options prefix-list bogon-ipv6 fc00::/7
set policy-options prefix-list bogon-ipv6 fec0::/10
set policy-options prefix-list bogon-ipv6 ff00::/8

Example firewall filters:
set firewall family inet filter inbound-ipv4 term 1 from source-prefix-list bogon-ipv4
set firewall family inet filter inbound-ipv4 term 1 then log
set firewall family inet filter inbound-ipv4 term 1 then syslog
set firewall family inet filter inbound-ipv4 term 1 then discard
set firewall family inet filter inbound-ipv4 term <permitted traffic terms>

set firewall family inet6 filter inbound-ipv6 term 1 from source-prefix-list bogon-ipv6
set firewall family inet6 filter inbound-ipv6 term 1 then log
set firewall family inet6 filter inbound-ipv6 term 1 then syslog
set firewall family inet6 filter inbound-ipv6 term 1 then discard
set firewall family inet6 filter inbound-ipv6 term <permitted traffic terms>

Example application on external interfaces:
set interfaces <interface name> unit <number> family inet filter input inbound-ipv4
set interfaces <interface name> unit <number> family inet address <IPv4 address / mask>

set interfaces <interface name> unit <number> family inet6 filter input inbound-ipv6
set interfaces <interface name> unit <number> family inet6 address <IPv6 address / prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57498r844169_chk'
  tag severity: 'medium'
  tag gid: 'V-254046'
  tag rid: 'SV-254046r844171_rule'
  tag stig_id: 'JUEX-RT-000740'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-57449r844170_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
