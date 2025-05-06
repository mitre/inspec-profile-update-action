control 'SV-254016' do
  title 'The Juniper PE router must be configured to block any traffic that is destined to IP core infrastructure.'
  desc 'IP/MPLS networks providing VPN and transit services must provide, at the least, the same level of protection against denial-of-service (DoS) attacks and intrusions as layer 2 networks. Although the IP core network elements are hidden, security should never rely entirely on obscurity.

IP addresses can be guessed. Core network elements must not be accessible from any external host. Protecting the core from any attack is vital for the integrity and privacy of customer traffic as well as the availability of transit services. A compromise of the IP core can result in an outage or, at a minimum, nonoptimized forwarding of customer traffic. Protecting the core from an outside attack also prevents attackers from using the core to attack any customer. Hence, it is imperative that all routers at the edge deny traffic destined to any address belonging to the IP core infrastructure.'
  desc 'check', 'Review the PE router configuration to verify that an ingress firewall filter is applied to all CE-facing interfaces. 

Verify that the ingress firewall filter rejects and logs packets destined to the IP core address block. For example:
[edit policy-options]
prefix-list ipv4-core {
    192.0.2.0/24;
}
prefix-list ipv6-core {
    2001:db8:2::/64;
}

[edit firewall]
family inet {
    filter deny-core-ipv4 {
        term 1 {
            from {
                destination-prefix-list {
                    ipv4-core;
                }
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        term default {
            then accept;
        }
    }
}
family inet6 {
    filter deny-core-ipv6 {
        term 1 {
            from {
                destination-prefix-list {
                    ipv6-core;
                }
            }
            then {
                log;
                syslog;
                discard;
            }
        }
        term default {
            then accept;
        }
    }
}

Verify the firewall filter is applied to CE-facing interfaces:
[edit interfaces]
ge-0/0/0 {
    unit 0 {
        family inet {
            filter {
                input deny-core-ipv4;   
            }                           
            address <IPv4 address/mask>;         
        }                               
        family inet6 {                  
            filter {                    
                input deny-core-ipv6;   
            }                           
            address <IPv6 address/prefix>;     
        }                               
    }                                   
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the PE router is not configured to block any traffic with a destination address assigned to the IP core infrastructure, this is a finding.

Note: Internet Control Message Protocol (ICMP) echo requests and traceroutes will be allowed to the edge from external adjacent peers.'
  desc 'fix', 'Configure protection for the IP core to be implemented at the edges by blocking any traffic with a destination address assigned to the IP core infrastructure.

Configure appropriate prefix lists and firewall filters. For example:
set policy-options prefix-list ipv4-core 192.0.2.0/24
set policy-options prefix-list ipv6-core 2001:db8:2::/64

set firewall family inet filter deny-core-ipv4 term 1 from destination-prefix-list ipv4-core
set firewall family inet filter deny-core-ipv4 term 1 then log
set firewall family inet filter deny-core-ipv4 term 1 then syslog
set firewall family inet filter deny-core-ipv4 term 1 then discard
set firewall family inet filter deny-core-ipv4 term default then accept
set firewall family inet6 filter deny-core-ipv6 term 1 from destination-prefix-list ipv6-core
set firewall family inet6 filter deny-core-ipv6 term 1 then log
set firewall family inet6 filter deny-core-ipv6 term 1 then syslog
set firewall family inet6 filter deny-core-ipv6 term 1 then discard
set firewall family inet6 filter deny-core-ipv6 term default then accept

Configure the appropriate interfaces with the firewall filter. For example:
[edit interfaces]
set interfaces ge-0/0/0 unit 0 family inet filter input deny-core-ipv4
set interfaces ge-0/0/0 unit 0 family inet address <IPv4 address/mask>
set interfaces ge-0/0/0 unit 0 family inet6 filter input deny-core-ipv6
set interfaces ge-0/0/0 unit 0 family inet6 address <IPv6 address/prefix>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57468r844079_chk'
  tag severity: 'high'
  tag gid: 'V-254016'
  tag rid: 'SV-254016r844081_rule'
  tag stig_id: 'JUEX-RT-000440'
  tag gtitle: 'SRG-NET-000205-RTR-000007'
  tag fix_id: 'F-57419r844080_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
