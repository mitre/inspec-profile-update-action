control 'SV-254009' do
  title 'The Juniper perimeter router must be configured to deny network traffic by default and allow network traffic by exception.'
  desc 'A deny-all, permit-by-exception network communications traffic policy ensures that only connections that are essential and approved are allowed.

This requirement applies to both inbound and outbound network communications traffic. All inbound and outbound traffic must be denied by default. Firewalls and perimeter routers should only allow traffic through that is explicitly permitted. The initial defense for the internal network is to block any traffic at the perimeter that is attempting to make a connection to a host residing on the internal network. In addition, allowing unknown or undesirable outbound traffic by the firewall or router will establish a state that will permit the return of this undesirable traffic inbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that the firewall filter is configured to allow specific ports and protocols and deny all other traffic. Associating any firewall filter to an interface will create a deny-all, permit-by-exception posture because each filter includes an implicit "deny all" final term. Verify firewall filters applied inbound on external interfaces are configured with terms permitting specific traffic.

For example:
[edit firewall]
family inet {
    filter permitted_inbound_traffic_ipv4 {
        term 1 {
            from {
                destination-prefix-list {
                    INSIDE_ADDRESSES_IPv4;
                }
                protocol tcp;
                destination-port [ http https ];
            }
            then accept;
        }
        term 2 {
            from {
                destination-prefix-list {
                    INSIDE_ADDRESSES_IPv4;
                }
                protocol udp;
                destination-port [ domain radius ];
            }
            then accept;
        }
    }
}
family inet6 {
    filter permitted_inbound_traffic_ipv6 {
        term 1 {
            from {
                destination-prefix-list {
                    INSIDE_ADDRESSES_IPv6;
                }
                next-header tcp;
                destination-port [ http https ];
            }
            then accept;
        }
        term 2 {
            from {
                destination-prefix-list {
                    INSIDE_ADDRESSES_IPv6;
                }
                next-header udp;
                destination-port [ domain radius ];
            }
            then accept;
        }
    }
}

Note: Although the example filter is sufficient to meet this requirement, an explicit "deny-all" term is required for logging. For example, add the following final term to both filters (IPv4 and IPv6) to enable logging of discarded packets:
[edit firewall family (inet|inet6) filter <name>]
term default {
    then {
        log;
        syslog;
        discard;
    }
}

The filter must be configured inbound on all external interfaces.
[edit interfaces]
<external interface> {
    unit <number> {
        family inet {
            filter input permitted_inbound_traffic_ipv4;
            address <IPv4 address/mask>;
        }
        family inet6 {
            filter input permitted_inbound_traffic_ipv6;
            address <IPv6 address/prefix>;
        }
}
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If the filter is not configured to allow specific ports and protocols and deny all other traffic, this is a finding.

If the filter is not configured inbound on all external interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the perimeter router to deny network traffic by default and allow network traffic by exception. For example:

set firewall family inet filter permitted_inbound_traffic_ipv4 term 1 from destination-prefix-list INSIDE_ADDRESSES
set firewall family inet filter permitted_inbound_traffic_ipv4 term 1 from protocol tcp
set firewall family inet filter permitted_inbound_traffic_ipv4 term 1 from destination-port http
set firewall family inet filter permitted_inbound_traffic_ipv4 term 1 from destination-port https
set firewall family inet filter permitted_inbound_traffic_ipv4 term 1 then accept
set firewall family inet filter permitted_inbound_traffic_ipv4 term 2 from destination-prefix-list INSIDE_ADDRESSES
set firewall family inet filter permitted_inbound_traffic_ipv4 term 2 from protocol udp
set firewall family inet filter permitted_inbound_traffic_ipv4 term 2 from destination-port domain
set firewall family inet filter permitted_inbound_traffic_ipv4 term 2 from destination-port radius
set firewall family inet filter permitted_inbound_traffic_ipv4 term 2 then accept

set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 1 from destination-prefix-list INSIDE_ADDRESSES
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 1 from next-header tcp
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 1 from destination-port http
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 1 from destination-port https
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 1 then accept
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 2 from destination-prefix-list INSIDE_ADDRESSES
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 2 from next-header udp
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 2 from destination-port domain
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 2 from destination-port radius
set firewall family inet6 filter permitted_inbound_traffic_ipv6 term 2 then accept

Note: To enable logging, add the following as the final term to each filter:
set firewall family [inet|inet6] filter <name> term default then log
set firewall family [inet|inet6] filter <name> term default then syslog
set firewall family [inet|inet6] filter <name> term default then discard

set interfaces <external interface> unit 0 family inet filter input permitted_inbound_traffic_ipv4
set interfaces <external interface> unit 0 family inet address <IPv4 address / mask>
set interfaces <external interface> unit 0 family inet6 filter input permitted_inbound_traffic_ipv6
set interfaces <external interface> unit 0 family inet6 address <IPv6 address / prefix>'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57461r844058_chk'
  tag severity: 'high'
  tag gid: 'V-254009'
  tag rid: 'SV-254009r844060_rule'
  tag stig_id: 'JUEX-RT-000370'
  tag gtitle: 'SRG-NET-000202-RTR-000001'
  tag fix_id: 'F-57412r844059_fix'
  tag 'documentable'
  tag cci: ['CCI-001109']
  tag nist: ['SC-7 (5)']
end
