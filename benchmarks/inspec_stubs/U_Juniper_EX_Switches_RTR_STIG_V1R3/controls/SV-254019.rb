control 'SV-254019' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC.

Review the OOBM gateway router configuration to validate the path that the management traffic traverses.

Verify that only management traffic is forwarded through the OOBM interface or IPsec tunnel. Verify the destination address is configured either via a prefix-list or directly assigned addresses in each firewall filter term match condition.

[edit policy-options]
prefix-list NOC-ipv4 {
    <IPv4 address>/<mask>;
}
prefix-list NOC-ipv6 {
    <IPv6 address>/<prefix>;
}
[edit firewall]
family inet {
    filter permit-NOC-ipv4 {
        term 1 {
            from {
                destination-prefix-list {
                    NOC-ipv4;
                }
                protocol <protocol>;
                destination-port [ <port 1> <port 2> ];
            }
            then accept;
        }
        <additional permitted traffic terms>
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
    filter permit-NOC-ipv6 {
        term 1 {
            from {
                destination-prefix-list {
                    NOC-ipv6;
                }
                next-header <protocol>;
                destination-port [ <port 1> <port 2> ];
            }
            then accept;
        }
        <additional permitted traffic terms>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
[edit interfaces]
<OOBM interface> {
    unit <number> {
        family inet {
            filter {
                output NOC-ipv4;   
            }                           
            address <IPv4 address>/<mask>;         
        }                               
        family inet6 {                  
            filter {                    
                output NOC-ipv6;   
            }                           
            address <IPv6 address>/<prefix>;     
        }                               
    }                                   
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If using an IPsec tunnel, verify the route with the tunnel interface as the next-hop destination.
[edit routing-options]
rib inet6.0 {
    static {
        route <NOC IPv6 network> next-hop <(tunnel interface | NOC IPv6 tunnel endpoint address)>;
    }
}
static { 
    route <NOC IPv4 network> next-hop <(tunnel interface | NOC IPv6 tunnel endpoint address)>;
}

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'Configure appropriate prefix lists and firewall filters. For example:
set policy-options prefix-list NOC-ipv4 <IPv4 network>/<mask>
set policy-options prefix-list NOC-ipv6 <IPv6 network>/<prefix>

set firewall family inet filter permit-NOC-ipv4 term 1 from destination-prefix-list NOC-ipv4
set firewall family inet filter permit-NOC-ipv4 term 1 from protocol <protocol>
set firewall family inet filter permit-NOC-ipv4 term 1 from destination-port [ <port 1> <port 2> ]
set firewall family inet filter permit-NOC-ipv4 term 1 then accept
<additional permit terms>
set firewall family inet filter permit-NOC-ipv4 term default then log
set firewall family inet filter permit-NOC-ipv4 term default then syslog
set firewall family inet filter permit-NOC-ipv4 term default then discard

set firewall family inet6 filter permit-NOC-ipv6 term 1 from destination-prefix-list NOC-ipv6
set firewall family inet6 filter permit-NOC-ipv6 term 1 from next-header <protocol>
set firewall family inet6 filter permit-NOC-ipv6 term 1 from destination-port [ <port 1> <port 2> ]
set firewall family inet6 filter permit-NOC-ipv6 term 1 then accept
<additional permit terms>
set firewall family inet6 filter permit-NOC-ipv6 term default then log
set firewall family inet6 filter permit-NOC-ipv6 term default then syslog
set firewall family inet6 filter permit-NOC-ipv6 term default then discard

Apply firewall filter to OOBM interface:
set interfaces <OOBM interface> unit <number> family inet filter output NOC-ipv4
set interfaces <OOBM interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <OOBM interface> unit <number> family inet6 filter output NOC-ipv6
set interfaces <OOBM interface> unit <number> family inet6 address <IPv6 address>/<prefix>

If using IPsec tunnel:
set rib inet6.0 static route <NOC IPv6 network> next-hop <(tunnel interface | NOC IPv6 tunnel endpoint address)>
set static route <NOC IPv4 network> next-hop <(tunnel interface | NOC IPv4 tunnel endpoint address)>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57471r844088_chk'
  tag severity: 'medium'
  tag gid: 'V-254019'
  tag rid: 'SV-254019r844090_rule'
  tag stig_id: 'JUEX-RT-000470'
  tag gtitle: 'SRG-NET-000205-RTR-000010'
  tag fix_id: 'F-57422r844089_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
