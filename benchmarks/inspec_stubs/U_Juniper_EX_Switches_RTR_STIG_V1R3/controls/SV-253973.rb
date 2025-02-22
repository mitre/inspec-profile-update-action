control 'SV-253973' do
  title 'The Juniper router must be configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies.'
  desc 'Information flow control regulates where information is allowed to travel within a network and between interconnected networks. The flow of all network traffic must be monitored and controlled so it does not introduce any unacceptable risk to the network infrastructure or data. Information flow control policies and enforcement mechanisms are commonly employed by organizations to control the flow of information between designated sources and destinations (e.g., networks, individuals, and devices) within information systems.

Enforcement occurs, for example, in boundary protection devices (e.g., gateways, routers, guards, encrypted tunnels, and firewalls) that employ rule sets or establish configuration settings that restrict information system services, provide a packet filtering capability based on header information, or provide a message filtering capability based on message content (e.g., implementing key word searches or using document characteristics).'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that stateless firewall filters are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. Verify the IP addresses are appropriate for the target environment. IP addresses are configured in lists at [edit policy-options] or are directly embedded into each term.

[edit policy-options]
prefix-list inside-addresses-ipv4 {
    <inside IPv4 subnet>/<mask>;
    <inside IPv4 subnet>/<mask>;
}
prefix-list inside-addresses-ipv6 {
    <inside IPv6 subnet>/<prefix>;
    <inside IPv6 subnet>/<prefix>;
}

For example:
[edit firewall]
family inet {
    filter authorized-outbound-ipv4 {
        term permitted-http {
            from {
                source-prefix-list {
                    inside-addresses-ipv4;
                }
                destination-address {
                    <destination IPv4 address>/<mask>;
                }
                protocol tcp;
                destination-port http;
            }
            then accept;
        }
        :
        <other terms>
        :
        term permitted-source-addresses {
            from {
                source-prefix-list {
                    inside-addresses-ipv4;
                }
                protocol-except tcp;
                destination-port-except http;
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
        term permitted-http {
            from {
                source-prefix-list {
                    inside-addresses-ipv6;
                }
                destination-address {
                    <destination IPv6 address>/<prefix>;
                }
                next-header tcp;
                destination-port http;
            }
            then accept;
        }
        :
        <other terms>
        :
        term permitted-source-addresses {
            from {
                source-prefix-list {
                    inside-addresses-ipv6;
                }
                next-header-except tcp;
                destination-port-except http;
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

Verify filters are applied to the correct interface. For example, the "authorized-outbound" filter, as written, should be applied to the ingress of internal interfaces:
[edit interfaces]
<internal interface name> {                             
    unit <number> {                            
        family inet {                   
            filter {                    
                input authorized-outbound-ipv4;             
            }                           
            address <IPv4 address>/<mask>;       
        }                               
        family inet6 {                   
            filter {                    
                input authorized-outbound-ipv6;             
            }                           
            address <IPv6 address>/<prefix>;       
        }                               
    }                                   
} 
Note: Some Juniper devices support both monolithic filters and filter lists. Filter lists separate each term, or set of terms, into a separate filter that is applied sequentially to an interface. If using filter lists, the keywords "input" and "output" change to "input-list" or "output-list". Verify the final list item is a deny-all filter. 

If the router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure stateless firewall filters to allow or deny traffic for specific source and destination addresses as well as ports and protocols.

Example prefix-lists:
set policy-options prefix-list inside-addresses-ipv4 <inside IPv4 subnet>
set policy-options prefix-list inside-addresses-ipv6 <inside IPv6 subnet>

Example firewall filter:
set firewall family inet filter authorized-outbound-ipv4 term permitted-source-addresses from source-prefix-list inside-addresses-ipv4
set firewall family inet filter authorized-outbound-ipv4 term permitted-source-addresses then accept
set firewall family inet filter authorized-outbound-ipv4 term 2 then log
set firewall family inet filter authorized-outbound-ipv4 term 2 then syslog
set firewall family inet filter authorized-outbound-ipv4 term 2 then discard

set firewall family inet6 filter authorized-outbound-ipv6 term permitted-source-addresses from source-prefix-list inside-addresses-ipv6
set firewall family inet6 filter authorized-outbound-ipv6 term permitted-source-addresses then accept
set firewall family inet6 filter authorized-outbound-ipv6 term 2 then log
set firewall family inet6 filter authorized-outbound-ipv6 term 2 then syslog
set firewall family inet6 filter authorized-outbound-ipv6 term 2 then discard

Example firewall filter applied to ingress of internal interface:
set interfaces <interface name> unit <number> family inet filter input authorized-outbound-ipv4
set interfaces <interface name> unit <number> family inet address <IPv4 address>/<mask>
set interfaces <interface name> unit <number> family inet6 filter input authorized-outbound-ipv6
set interfaces <interface name> unit <number> family inet6 address <IPv6 address>/<prefix>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57425r843950_chk'
  tag severity: 'medium'
  tag gid: 'V-253973'
  tag rid: 'SV-253973r843952_rule'
  tag stig_id: 'JUEX-RT-000010'
  tag gtitle: 'SRG-NET-000018-RTR-000001'
  tag fix_id: 'F-57376r843951_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
