control 'SV-254052' do
  title 'The Juniper Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

[edit firewall]
family inet {
    filter <name> {
        term 1 {
            from {
                source-prefix-list {
                    msdp-peers; 
                }
                protocol tcp;
                destination-port msdp;
            }
            then accept;
        }
        term 2 {
            from {
                source-prefix-list {
                    msdp-peers;
                }
                protocol tcp;
                source-port msdp;
            }
            then accept;
        }
        <additional terms>
        term default {
            then {
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter <name> {
        term 1 {
            from {
                source-prefix-list {
                    msdp-peers-ipv6;
                }
                next-header tcp;
                destination-port msdp;
            }
            then accept;
        }
        term 2 {
            from {
                source-prefix-list {
                    msdp-peers-ipv6;
                }
                next-header tcp;
                source-port msdp;
            }
            then accept;
        }
        <additional terms>
        term default {
            then {
                syslog;
                discard;
            }
        }
    }
}

Note: Some platforms support the "port" keyword that filters on both source- and destination-port, which eliminates the need for separate terms. For instance:
filter <name> {
    term 1 {
        from {
            source-prefix-list {
                <prefix list name>;
            }
            [protocol|next-header] tcp;
            port msdp;
        }
        then accept;
    }
    <additional terms>
    term default {
        then {
            syslog;
            discard;
        }
    }
}

Verify the filter is applied to external interfaces or loopback.
[edit interfaces]
<external interface> {
    unit <number> {
        family inet {
            filter {
                input <IPv4 filter name>;
            }
            address <IPv4 address>/<mask>;
        }
        family inet6 {
            filter {
                input <IPv6 filter name>;
            }
            address <IPv6 address>/<prefix>;
        }
    }
}
lo0 {
    unit <number> {
        family inet {
            filter {
                input <IPv4 filter name>;
            }
            address <IPv4 address>/32;
        }
        family inet6 {
            filter {
                input <IPv6 filter name>;
            }
            address <IPv6 address>/128;
        }
    }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Ensure the receive path or interface filter for all MSDP routers only accepts MSDP packets from known MSDP peers.

set firewall family inet filter <name> term 1 from source-prefix-list msdp-peers
set firewall family inet filter <name> term 1 from protocol tcp
set firewall family inet filter <name> term 1 from destination-port msdp
set firewall family inet filter <name> term 1 then accept
set firewall family inet filter <name> term 2 from source-prefix-list msdp-peers
set firewall family inet filter <name> term 2 from protocol tcp
set firewall family inet filter <name> term 2 from source-port msdp
set firewall family inet filter <name> term 2 then accept
<additional terms>
set firewall family inet filter <name> term default then syslog
set firewall family inet filter <name> term default then discard

set firewall family inet6 filter <name> term 1 from source-prefix-list msdp-peers-ipv6
set firewall family inet6 filter <name> term 1 from next-header tcp
set firewall family inet6 filter <name> term 1 from destination-port msdp
set firewall family inet6 filter <name> term 1 then accept
set firewall family inet6 filter <name> term 2 from source-prefix-list msdp-peers-ipv6
set firewall family inet6 filter <name> term 2 from next-header tcp
set firewall family inet6 filter <name> term 2 from source-port msdp
set firewall family inet6 filter <name> term 2 then accept
<additional terms>
set firewall family inet6 filter <name> term default then syslog
set firewall family inet6 filter <name> term default then discard

set interfaces <external interface> unit <number> family inet filter input <IPv4 filter name>
set interfaces <external interface> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <external interface> unit <number> family inet6 filter input <IPv6 filter name>
set interfaces <external interface> unit <number> family inet6 address <IPv6 address>/<prefix>

set interfaces lo0 unit <number> family inet filter input <IPv4 filter name>
set interfaces lo0 unit <number> family inet address <IPv4 address>/32
set interfaces lo0 unit <number> family inet6 filter input <IPv6 filter name>
set interfaces lo0 unit <number> family inet6 address <IPv6 address>/128'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57504r844187_chk'
  tag severity: 'medium'
  tag gid: 'V-254052'
  tag rid: 'SV-254052r844189_rule'
  tag stig_id: 'JUEX-RT-000800'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-57455r844188_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
