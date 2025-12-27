control 'SV-254022' do
  title 'The Juniper perimeter router must be configured to restrict it from accepting outbound IP packets that contain an illegitimate address in the source address field via egress filter or by enabling Unicast Reverse Path Forwarding (uRPF).'
  desc 'A compromised host in an enclave can be used by a malicious platform to launch cyberattacks on third parties. This is a common practice in "botnets", which are a collection of compromised computers using malware to attack other computers or networks. DDoS attacks frequently leverage IP source address spoofing to send packets to multiple hosts that in turn will then send return traffic to the hosts with the IP addresses that were forged. This can generate significant amounts of traffic. Therefore, protection measures to counteract IP source address spoofing must be taken. When uRPF is enabled in strict mode, the packet must be received on the interface that the device would use to forward the return packet; thereby mitigating IP source address spoofing.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify uRPF or an egress filter has been configured on all internal interfaces to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field.

[edit interfaces]
<internal interface name> {
    unit <number> {
        family inet {
            rpf-check;
            address <IPv4 address>/<mask>;         
        }                               
        family inet6 {                  
            rpf-check;
            address <IPv6 address>/<prefix>;     
        }                               
    }                                   
}

For those platforms that do not support uRPF, verify an egress stateless firewall filter is applied to all internal interfaces. In this example, the egress (from the enclave) filter is applied in the input direction of internal interfaces to prevent the router from accepting packets sourced from any address except the internal subnets. For example:
[edit policy-options]
prefix-list internal-prefixes-ipv4 {
    192.0.2.0/24;
}
prefix-list internal-prefixes-ipv6 {
    2001:0:2::/64;
}
[edit firewall]
family inet {
    filter internal-inbound-ipv4 {
        term 1 {
            from {
                source-prefix-list {
                    internal-prefixes-ipv4;
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
    filter internal-inbound-ipv6 {
        term 1 {
            from {
                source-prefix-list {
                    internal-prefixes-ipv6;
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

Verify the appropriate filter is applied to each internal interface. For example:
[edit interfaces]
<internal interface name> {
    unit <number> {
        family inet {
            filter {
                input internal-inbound-ipv4;
            }                           
            address <IPv4 address>/<mask>;       
        }                               
        family inet6 {                  
            filter {                    
                input internal-inbound-ipv6;
            }                           
            address <IPv6 address>/<prefix>;     
        }                               
    }                                   
}

Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" or "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. The deny-all filter is created once per family and can be reused across multiple lists. For example:

input-list [ permit_mgt permit_routing_protocols default-deny ];

If uRPF or an egress filter to restrict the router from accepting outbound IP packets that contain an illegitimate address in the source address field has not been configured on all internal interfaces, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router to ensure that an egress filter or uRPF is configured to restrict the router from accepting any outbound IP packet that contains an external IP address in the source field.

set interfaces <internal interface name> unit <number> family inet rpf-check
set interfaces <internal interface name> unit <number> family inet6 rpf-check

For example, configure firewall filter and apply to internal interfaces:
set policy-options prefix-list internal-prefixes-ipv4 192.0.2.0/24
set policy-options prefix-list internal-prefixes-ipv6 2001:0:2::/64

set firewall family inet filter internal-inbound-ipv4 term 1 from source-prefix-list internal-prefixes-ipv4
set firewall family inet filter internal-inbound-ipv4 term 1 then accept
set firewall family inet filter internal-inbound-ipv4 term default then log
set firewall family inet filter internal-inbound-ipv4 term default then syslog
set firewall family inet filter internal-inbound-ipv4 term default then discard
set firewall family inet6 filter internal-inbound-ipv6 term 1 from source-prefix-list internal-prefixes-ipv6
set firewall family inet6 filter internal-inbound-ipv6 term 1 then accept
set firewall family inet6 filter internal-inbound-ipv6 term default then log
set firewall family inet6 filter internal-inbound-ipv6 term default then syslog
set firewall family inet6 filter internal-inbound-ipv6 term default then discard

set interfaces ge-0/0/0 unit 0 family inet filter input internal-inbound-ipv4
set interfaces ge-0/0/0 unit 0 family inet6 filter input internal-inbound-ipv6'
  impact 0.7
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57474r844097_chk'
  tag severity: 'high'
  tag gid: 'V-254022'
  tag rid: 'SV-254022r844099_rule'
  tag stig_id: 'JUEX-RT-000500'
  tag gtitle: 'SRG-NET-000205-RTR-000014'
  tag fix_id: 'F-57425r844098_fix'
  tag 'documentable'
  tag cci: ['CCI-001094']
  tag nist: ['SC-5 (1)']
end
