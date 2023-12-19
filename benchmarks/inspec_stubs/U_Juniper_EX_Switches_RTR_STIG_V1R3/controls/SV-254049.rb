control 'SV-254049' do
  title 'The Juniper perimeter router must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet to enforce control and access boundaries provided by layer 3 network nodes, such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

The perimeter router of the managed network must be configured with a firewall filter on the egress interface to block all management traffic.

[edit firewall]
family inet {
    filter <name> {
        term block-UDP-MGT-SRC {
            from {
                protocol udp;
                source-port [ snmp snmptrap 2055 9995 9996 ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-TCP-MGT-SRC {
            from {
                protocol tcp;
                source-port [ ssh tacacs ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-UDP-MGT-DST {
            from {
                protocol udp;
                destination-port [ snmp snmptrap 2055 9995 9996 ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-TCP-MGT-DST {
            from {
                protocol tcp;
                destination-port [ ssh tacacs ];
            }
            then {
                syslog;
                discard;
            }
        }
        <additional terms>
        term accept-other {
            then accept;
        }
    }
}
family inet6 {
    filter <name> {
        term block-UDP-MGT-SRC {
            from {
                next-header udp;
                source-port [ snmp snmptrap 2055 9995 9996 ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-TCP-MGT-SRC {
            from {
                next-header tcp;
                source-port [ ssh tacacs ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-UDP-MGT-DST {
            from {
                next-header udp;
                destination-port [ snmp snmptrap 2055 9995 9996 ];
            }
            then {
                syslog;
                discard;
            }
        }
        term block-TCP-MGT-DST {
            from {
                next-header tcp;
                destination-port [ ssh tacacs ];
            }
            then {
                syslog;
                discard;
            }
        }
        <additional terms>
        term accept-other {
            then accept;
        }
    }
}

Note: Some platforms support the "port" match criterion. For those platforms, only a single term is required to flag on both source- and destination-port. For example:
[edit firewall]
family [inet|inet6] {
    filter <name> {
        term <name> {
            from {
                :
                port [ port1 port2... ];
            }
            then {
                syslog;
                discard;
            }
        }
        <additional terms>
    }
}

Verify the filter is applied to external interfaces.
[edit interfaces]
<external interface> {
    unit <number> {
        family inet {
            filter {
                output <name>;
            }
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                output <name>;
            }
            address <IPv6 address>/<prefix>;
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the perimeter router of the managed network with a firewall filter on the egress interface to block all outbound management traffic.

set firewall family inet filter <name> term block-UDP-MGT-SRC from protocol udp
set firewall family inet filter <name> term block-UDP-MGT-SRC from source-port [ snmp snmptrap 2055 9995 9996 ]
set firewall family inet filter <name> term block-UDP-MGT-SRC then syslog 
set firewall family inet filter <name> term block-UDP-MGT-SRC then discard 
set firewall family inet filter <name> term block-TCP-MGT-SRC from protocol tcp
set firewall family inet filter <name> term block-TCP-MGT-SRC from source-port [ ssh tacacs ]
set firewall family inet filter <name> term block-TCP-MGT-SRC then syslog 
set firewall family inet filter <name> term block-TCP-MGT-SRC then discard 
set firewall family inet filter <name> term block-UDP-MGT-DST from protocol udp
set firewall family inet filter <name> term block-UDP-MGT-DST from destination-port [ snmp snmptrap 2055 9995 9996 ]
set firewall family inet filter <name> term block-UDP-MGT-DST then syslog 
set firewall family inet filter <name> term block-UDP-MGT-DST then discard 
set firewall family inet filter <name> term block-TCP-MGT-DST from protocol tcp
set firewall family inet filter <name> term block-TCP-MGT-DST from destination-port [ ssh tacacs ]
set firewall family inet filter <name> term block-TCP-MGT-DST then syslog 
set firewall family inet filter <name> term block-TCP-MGT-DST then discard 
<additional terms>
set firewall family inet filter <name> term accept-others then accept 

set firewall family inet6 filter <name> term block-UDP-MGT-SRC from next-header udp
set firewall family inet6 filter <name> term block-UDP-MGT-SRC from source-port [ snmp snmptrap 2055 9995 9996 ]
set firewall family inet6 filter <name> term block-UDP-MGT-SRC then syslog 
set firewall family inet6 filter <name> term block-UDP-MGT-SRC then discard 
set firewall family inet6 filter <name> term block-TCP-MGT-SRC from next-header tcp
set firewall family inet6 filter <name> term block-TCP-MGT-SRC from source-port [ ssh tacacs ]
set firewall family inet6 filter <name> term block-TCP-MGT-SRC then syslog 
set firewall family inet6 filter <name> term block-TCP-MGT-SRC then discard 
set firewall family inet6 filter <name> term block-UDP-MGT-DST from next-header udp
set firewall family inet6 filter <name> term block-UDP-MGT-DST from destination-port [ snmp snmptrap 2055 9995 9996 ]
set firewall family inet6 filter <name> term block-UDP-MGT-DST then syslog 
set firewall family inet6 filter <name> term block-UDP-MGT-DST then discard 
set firewall family inet6 filter <name> term block-TCP-MGT-DST from next-header tcp
set firewall family inet6 filter <name> term block-TCP-MGT-DST from destination-port [ ssh tacacs ]
set firewall family inet6 filter <name> term block-TCP-MGT-DST then syslog 
set firewall family inet6 filter <name> term block-TCP-MGT-DST then discard 
<additional terms>
set firewall family inet6 filter <name> term accept-others then accept 

set interfaces <external interface> unit <number> family inet filter output <name>
set interfaces <external interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <external interface> unit <number> family inet6 filter output <name>
set interfaces <external interface> unit <number> family inet6 address <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57501r844178_chk'
  tag severity: 'medium'
  tag gid: 'V-254049'
  tag rid: 'SV-254049r844180_rule'
  tag stig_id: 'JUEX-RT-000770'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-57452r844179_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
