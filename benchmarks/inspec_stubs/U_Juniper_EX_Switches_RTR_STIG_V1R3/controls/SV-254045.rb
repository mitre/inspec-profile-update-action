control 'SV-254045' do
  title 'The Juniper perimeter router must be configured to only allow incoming communications from authorized sources to be routed to authorized destinations.'
  desc "Unrestricted traffic may contain malicious traffic that poses a threat to an enclave or to other connected networks. Additionally, unrestricted traffic may transit a network, which uses bandwidth and other resources.

Traffic can be restricted directly by stateless firewall filter, or filter based forwarding. Filter based forwarding is a technique used to make routing decisions based on a number of different criteria other than just the destination network, including source or destination network, source or destination address, source or destination port, protocol, packet size, and packet classification. This overrides the router's normal routing procedures used to control the specific paths of network traffic. It is normally used for traffic engineering but can also be used to meet security requirements; for example, traffic that is not allowed can be routed to the discard interface. Filter based forwarding can also be used to control which prefixes appear in the routing table.

This requirement is intended to allow network administrators the flexibility to use whatever technique is most effective."
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to determine if the router allows only incoming communications from authorized sources to be routed to authorized destinations.

[edit policy-options]
prefix-list inside-addresses-ipv4 {
    192.0.2.0/25;
    192.0.2.130/32;
}
prefix-list inside-addresses-ipv6 {
    2001:db8:1::/64;
    2001:db8:a1::/64;
}

[edit firewall]
family inet {
    filter authorized-outbound-ipv4 {
        <additional terms>
        term permitted-source-addresses {
            from {
                source-prefix-list {
                    inside-addresses-ipv4;
                }
            }
            then accept;
        }
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
    filter authorized-inbound-ipv4 {
        <additional terms>
        term permitted-destination-addresses {
            from {
                destination-prefix-list {
                    inside-addresses-ipv4;
                }
            }
            then accept;
        }
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}
family inet6 {
    filter authorized-outbound-ipv6 {
        <additional terms>
        term permitted-source-addresses {
            from {
                source-prefix-list {
                    inside-addresses-ipv6;
                }
            }
            then accept;
        }
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
    filter authorized-inbound-ipv6 {
        <additional terms>
        term permitted-destination-addresses {
            from {
                destination-prefix-list {
                    inside-addresses-ipv6;
                }
            }
            then accept;
        }
        term default-deny {
            then {
                log;
                syslog;
                discard;
            }
        }
    }
}

Note: The same firewall filtering process can be configured to control traffic destined to the router, or between internal subnets.

Verify the firewall filters are applied to the correct interface in the appropriate direction.
[edit interfaces]
<external interface> {
    unit <number> {
        family inet {
            filter {
                input authorized-inbound-ipv4;
            }
            address <IPv4 address>.<mask>;
        }
        family inet6 {
            filter {
                input authorized-inbound-ipv6;
            }
            address <IPv6 address>.<prefix>;
        }
    }
}
<internal interface> {
    unit <number> {
        family inet {
            filter {
                input authorized-outbound-ipv4;
            }
            address <IPv4 address>.<mask>;
        }
        family inet6 {
            filter {
                input authorized-outbound-ipv6;
            }
            address <IPv6 address>.<prefix>;
        }
    }
}

If the router does not restrict incoming communications to allow only authorized sources and destinations, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to allow only incoming communications from authorized sources to be routed to authorized destinations.

set policy-options prefix-list inside-addresses-ipv4 192.0.2.0/25
set policy-options prefix-list inside-addresses-ipv4 192.0.2.130/32
set policy-options prefix-list inside-addresses-ipv6 2001:db8:1::/64
set policy-options prefix-list inside-addresses-ipv6 2001:db8:a1::/64

set firewall family inet filter authorized-outbound-ipv4 <additional terms>
set firewall family inet filter authorized-outbound-ipv4 term permitted-source-addresses from source-prefix-list inside-addresses-ipv4
set firewall family inet filter authorized-outbound-ipv4 term permitted-source-addresses then accept
set firewall family inet filter authorized-outbound-ipv4 term default-deny then log
set firewall family inet filter authorized-outbound-ipv4 term default-deny then syslog
set firewall family inet filter authorized-outbound-ipv4 term default-deny then discard

set firewall family inet filter authorized-inbound-ipv4 <additional terms>
set firewall family inet filter authorized-inbound-ipv4 term permitted-destination-addresses from destination-prefix-list inside-addresses-ipv4
set firewall family inet filter authorized-inbound-ipv4 term permitted-destination-addresses then accept
set firewall family inet filter authorized-inbound-ipv4 term default-deny then log
set firewall family inet filter authorized-inbound-ipv4 term default-deny then syslog
set firewall family inet filter authorized-inbound-ipv4 term default-deny then discard

set firewall family inet6 filter authorized-outbound-ipv6 <additional terms>
set firewall family inet6 filter authorized-outbound-ipv6 term permitted-source-addresses from source-prefix-list inside-addresses-ipv6
set firewall family inet6 filter authorized-outbound-ipv6 term permitted-source-addresses then accept
set firewall family inet6 filter authorized-outbound-ipv6 term default-deny then log
set firewall family inet6 filter authorized-outbound-ipv6 term default-deny then syslog
set firewall family inet6 filter authorized-outbound-ipv6 term default-deny then discard

set firewall family inet6 filter authorized-inbound-ipv6 <additional terms>
set firewall family inet6 filter authorized-inbound-ipv6 term permitted-destination-addresses from destination-prefix-list inside-addresses-ipv6
set firewall family inet6 filter authorized-inbound-ipv6 term permitted-destination-addresses then accept
set firewall family inet6 filter authorized-inbound-ipv6 term default-deny then log
set firewall family inet6 filter authorized-inbound-ipv6 term default-deny then syslog
set firewall family inet6 filter authorized-inbound-ipv6 term default-deny then discard

set interfaces <external interface> unit <number> family inet filter input authorized-inbound-ipv4
set interfaces <external interface> unit <number> family inet6 filter input authorized-inbound-ipv6

set interfaces <internal interface> unit <number> family inet filter input authorized-outbound-ipv4
set interfaces <internal interface> unit <number> family inet6 filter input authorized-outbound-ipv6'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57497r844166_chk'
  tag severity: 'medium'
  tag gid: 'V-254045'
  tag rid: 'SV-254045r844168_rule'
  tag stig_id: 'JUEX-RT-000730'
  tag gtitle: 'SRG-NET-000364-RTR-000109'
  tag fix_id: 'F-57448r844167_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
