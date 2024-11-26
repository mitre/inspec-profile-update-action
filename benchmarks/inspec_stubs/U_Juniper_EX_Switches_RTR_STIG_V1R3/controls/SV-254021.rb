control 'SV-254021' do
  title 'The Juniper router must be configured to only permit management traffic that ingresses and egresses the OOBM interface.'
  desc 'The OOBM access switch will connect to the management interface of the managed network elements. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will be directly connected to the OOBM network.

An OOBM interface does not forward transit traffic, thereby providing complete separation of production and management traffic. Because all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an OOBM interface, the interface functioning as the management interface must be configured so that management traffic does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Verify that the managed interface has an inbound and outbound firewall filter configured. In this example, the firewall filter uses prefix-lists rather than directly embedding the addresses in the filter term. Verify that the ingress filter only allows management, IGP, and ICMP traffic.

Caveat: If the management interface is a true OOBM interface, this requirement is not applicable.

[edit policy-options]
prefix-list OOBM-ipv4 {
    192.0.2.0/24;
}
prefix-list OOBM-ipv6 {
    2001:db8:2::/64;
}
[edit firewall]
family inet {
    filter inbound-OOBM-ipv4 {
        term 1 {
            from {
                source-prefix-list {
                    OOBM-ipv4;
                }
                protocol [ icmp ospf ];
            }
            then accept;
        }
        term 2 {
            from {
                source-prefix-list {
                    OOBM-ipv4;
                }
                protocol tcp;
                destination-port ssh;
            }
            then accept;
        }
        <additional permit terms>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
    filter outbound-OOBM-ipv4 {
        term 1 {
            from {
                destination-prefix-list {
                    OOBM-ipv4;
                }
                protocol [ icmp ospf ];
            }
            then accept;
        }
        term 2 {
            from {
                destination-prefix-list {
                    OOBM-ipv4;
                }
                protocol tcp;
                source-port ssh;
            }
            then accept;
        }
        <additional permit terms>
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
    filter inbound-OOBM-ipv6 {
        term 1 {
            from {
                source-prefix-list {
                    OOBM-ipv6;
                }
                next-header [ icmp6 ospf ];
            }
            then accept;
        }
        term 2 {
            from {
                source-prefix-list {
                    OOBM-ipv6;
                }
                next-header tcp;
                destination-port ssh;
            }
            then accept;
        }
        <additional permit terms>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
    filter outbound-OOBM-ipv6 {
        term 1 {
            from {
                destination-prefix-list {
                    OOBM-ipv6;
                }
                next-header [ icmp6 ospf ];
            }
            then accept;
        }
        term 2 {
            from {
                destination-prefix-list {
                    OOBM-ipv6;
                }
                next-header tcp;
                source-port ssh;
            }
            then accept;
        }
        <additional permit terms>
        term default {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

If no true OOBM interface is available, verify the OOBM firewall filter is applied to the revenue interface configured for OOBM use.

<revenue OOBM interface> {
    unit <number> {
        family inet {
            filter {
                input inbound-OOBM-ipv4;
                output outbound-OOBM-ipv4;
            }
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                input inbound-OOBM-ipv6;
                output outbound-OOBM-ipv6;
            }
            address <IPv6 address>/<prefix>;
        }
    }
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router does not restrict traffic that ingresses and egresses the management interface, this is a finding.'
  desc 'fix', 'If the management interface is a routed interface, it must be configured with both an ingress and egress ACL. 

set policy-options prefix-list OOBM-ipv4 192.0.2.0/24
set policy-options prefix-list OOBM-ipv6 2001:db8:2::/64

set firewall family inet filter inbound-OOBM-ipv4 term 1 from source-prefix-list OOBM-ipv4
set firewall family inet filter inbound-OOBM-ipv4 term 1 from protocol icmp
set firewall family inet filter inbound-OOBM-ipv4 term 1 from protocol ospf
set firewall family inet filter inbound-OOBM-ipv4 term 1 then accept
set firewall family inet filter inbound-OOBM-ipv4 term 2 from source-prefix-list OOBM-ipv4
set firewall family inet filter inbound-OOBM-ipv4 term 2 from protocol tcp
set firewall family inet filter inbound-OOBM-ipv4 term 2 from destination-port ssh
set firewall family inet filter inbound-OOBM-ipv4 term 2 then accept
<additional accept terms>
set firewall family inet filter inbound-OOBM-ipv4 term default then log
set firewall family inet filter inbound-OOBM-ipv4 term default then syslog
set firewall family inet filter inbound-OOBM-ipv4 term default then discard

set firewall family inet filter outbound-OOBM-ipv4 term 1 from destination-prefix-list OOBM-ipv4
set firewall family inet filter outbound-OOBM-ipv4 term 1 from protocol icmp
set firewall family inet filter outbound-OOBM-ipv4 term 1 from protocol ospf
set firewall family inet filter outbound-OOBM-ipv4 term 1 then accept
set firewall family inet filter outbound-OOBM-ipv4 term 2 from destination-prefix-list OOBM-ipv4
set firewall family inet filter outbound-OOBM-ipv4 term 2 from protocol tcp
set firewall family inet filter outbound-OOBM-ipv4 term 2 from source-port ssh
set firewall family inet filter outbound-OOBM-ipv4 term 2 then accept
<additional accept terms>
set firewall family inet filter outbound-OOBM-ipv4 term default then log
set firewall family inet filter outbound-OOBM-ipv4 term default then syslog
set firewall family inet filter outbound-OOBM-ipv4 term default then discard

set firewall family inet filter inbound-OOBM-ipv6 term 1 from source-prefix-list OOBM-ipv6
set firewall family inet filter inbound-OOBM-ipv6 term 1 from next-header icmp6
set firewall family inet filter inbound-OOBM-ipv6 term 1 from next-header ospf
set firewall family inet filter inbound-OOBM-ipv6 term 1 then accept
set firewall family inet filter inbound-OOBM-ipv6 term 2 from source-prefix-list OOBM-ipv6
set firewall family inet filter inbound-OOBM-ipv6 term 2 from next-header tcp
set firewall family inet filter inbound-OOBM-ipv6 term 2 from destination-port ssh
set firewall family inet filter inbound-OOBM-ipv6 term 2 then accept
<additional accept terms>
set firewall family inet filter inbound-OOBM-ipv6 term default then log
set firewall family inet filter inbound-OOBM-ipv6 term default then syslog
set firewall family inet filter inbound-OOBM-ipv6 term default then discard

set firewall family inet6 filter outbound-OOBM-ipv6 term 1 from destination-prefix-list OOBM-ipv6
set firewall family inet6 filter outbound-OOBM-ipv6 term 1 from next-header icmp6
set firewall family inet6 filter outbound-OOBM-ipv6 term 1 from next-header ospf
set firewall family inet6 filter outbound-OOBM-ipv6 term 1 then accept
set firewall family inet6 filter outbound-OOBM-ipv6 term 2 from destination-prefix-list OOBM-ipv6
set firewall family inet6 filter outbound-OOBM-ipv6 term 2 from next-header tcp
set firewall family inet6 filter outbound-OOBM-ipv6 term 2 from source-port ssh
set firewall family inet6 filter outbound-OOBM-ipv6 term 2 then accept
<additional accept terms>
set firewall family inet6 filter outbound-OOBM-ipv6 term default then log
set firewall family inet6 filter outbound-OOBM-ipv6 term default then syslog
set firewall family inet6 filter outbound-OOBM-ipv6 term default then discard

set interfaces <revenue OOBM> unit <number> family inet filter input inbound-OOBM-ipv4
set interfaces <revenue OOBM> unit <number> family inet filter output outbound-OOBM-ipv4
set interfaces <revenue OOBM> unit <number> family inet <IPv4 address>/<mask>
set interfaces <revenue OOBM> unit <number> family inet6 filter input inbound-OOBM-ipv6
set interfaces <revenue OOBM> unit <number> family inet6 filter output outbound-OOBM-ipv6
set interfaces <revenue OOBM> unit <number> family inet6 <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57473r844094_chk'
  tag severity: 'medium'
  tag gid: 'V-254021'
  tag rid: 'SV-254021r844096_rule'
  tag stig_id: 'JUEX-RT-000490'
  tag gtitle: 'SRG-NET-000205-RTR-000012'
  tag fix_id: 'F-57424r844095_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
