control 'SV-254017' do
  title 'The Juniper PE router must be configured with Unicast Reverse Path Forwarding (uRPF) loose mode, or a firewall filter, enabled on all CE-facing interfaces.'
  desc 'The uRPF feature, and ingress firewall filters, are defenses against spoofing and denial-of-service (DoS) attacks by verifying if the source address of any ingress packet is reachable. To mitigate attacks that rely on forged source addresses, all provider edge routers must enable uRPF or ingress firewall filters to guarantee that all packets received from a CE router contain source addresses that are in the route table.'
  desc 'check', %q(Review the PE router configuration to determine if uRPF loose mode is enabled on all CE-facing interfaces.

[edit interfaces]
ge-0/0/12 {
    unit 0 {
        family inet {
            rpf-check {                 
                mode loose;             
            }                           
            address <IPv4 address>/<mask>;         
        }                               
        family inet6 {                  
            rpf-check {                 
                mode loose;             
            }                           
            address <IPv6 address>/<prefix>;     
        }                               
    }                                   
}

For those platforms that do not support uRPF, verify an ingress stateless firewall filter is applied to all CE-facing interfaces. Because the prefixes assigned to each customer is known, verify each customer's prefix list contains only their prefixes and is referenced in an appropriate firewall filter. For example:
[edit policy-options]
prefix-list cust1-prefixes-ipv4 {
    192.0.2.0/24;
}
prefix-list cust1-prefixes-ipv6 {
    2001:db8:2::/64;
}
[edit firewall]
family inet {
    filter cust1-prefixes-ipv4 {
        term 1 {
            from {
                source-prefix-list {
                    cust1-prefixes-ipv4;
                }
            }
            then accept;
        }
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter cust1-prefixes-ipv6 {
        term 1 {
            from {
                source-prefix-list {
                    cust1-prefixes-ipv6;
                }
            }
            then accept;
        }
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

Verify the appropriate filter is applied to each CE-facing interface. For example:
[edit interfaces]
ge-0/0/0 {
    unit 0 {
        family inet {
            filter {
                input cust1-prefixes-ipv4;
            }                           
            address <IPv4 address>/<mask>;       
        }                               
        family inet6 {                  
            filter {                    
                input cust1-prefixes-ipv6;
            }                           
            address <IPv6 address>/<prefix>;     
        }                               
    }                                   
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If uRPF or an ingress firewall filter is not enabled on all CE-facing interfaces, this is a finding.)
  desc 'fix', 'Enable uRPF loose mode or apply an ingress filter on all CE-facing interfaces.

For example, configure uRPF on CE-facing interfaces:
set interfaces ge-0/0/0 unit 0 family inet rpf-check mode loose
set interfaces ge-0/0/0 unit 0 family inet6 rpf-check mode loose

For example, configure firewall filter and apply to CE-facing interfaces (only for devices that do not support uRPF):
set policy-options prefix-list cust1-prefixes-ipv4 192.0.2.0/24
set policy-options prefix-list cust1-prefixes-ipv6 2001:db8:2::/64

set firewall family inet filter cust1-prefixes-ipv4 term 1 from source-prefix-list cust1-prefixes-ipv4
set firewall family inet filter cust1-prefixes-ipv4 term 1 then accept
set firewall family inet filter cust1-prefixes-ipv4 term default then log
set firewall family inet filter cust1-prefixes-ipv4 term default then syslog
set firewall family inet filter cust1-prefixes-ipv4 term default then discard
set firewall family inet6 filter cust1-prefixes-ipv6 term 1 from source-prefix-list cust1-prefixes-ipv6
set firewall family inet6 filter cust1-prefixes-ipv6 term 1 then accept
set firewall family inet6 filter cust1-prefixes-ipv6 term default then log
set firewall family inet6 filter cust1-prefixes-ipv6 term default then syslog
set firewall family inet6 filter cust1-prefixes-ipv6 term default then discard

set interfaces ge-0/0/0 unit 0 family inet filter input cust1-prefixes-ipv4
set interfaces ge-0/0/0 unit 0 family inet6 filter input cust1-prefixes-ipv6'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57469r844082_chk'
  tag severity: 'medium'
  tag gid: 'V-254017'
  tag rid: 'SV-254017r844084_rule'
  tag stig_id: 'JUEX-RT-000450'
  tag gtitle: 'SRG-NET-000205-RTR-000008'
  tag fix_id: 'F-57420r844083_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
