control 'SV-233295' do
  title 'The Juniper perimeter router must be configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values.'
  desc 'These options are intended to be for the Destination Options header only. The optional and extensible natures of the IPv6 extension headers require higher scrutiny since many implementations do not always drop packets with headers that it cannot recognize and hence could cause a Denial-of-Service on the target device. In addition, the type, length, value (TLV) formatting provides the ability for headers to be very large.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if ACLs are bound to the applicable interfaces to drop IPv6 packets containing a Hop-by-Hop header with option type values of 0x04 (Tunnel Encapsulation Limit), 0xC9 (Home Address Destination), or 0xC3 (NSAP Address).  

Step 1: Verify that all external IPv6-enabled interfaces have an IPv6 filter as shown in the example below.

interfaces {
    ge-0/0/0  {
        unit 0 {
            family inet6 {
                filter {
                    input IPV6-INGRESS-FILTER;
                }
                address 2001:1:0:146::1/64;
            }
        }
    }
}

Step 2: Verify that the IPV6 filter blocks all packets with a Hop-by-Hop header as shown in the example below.

firewall {
    family inet6 {
        filter IPV6-INGRESS-FILTER {
            term HOP_BY_HOP_HEADER {
                from {
                    next-header hop-by-hop;
                }
                then {
                    syslog;
                    discard;
                }
            }
            term ALLOW_TCP_ESTABLISHED {
                from {
                    next-header tcp;
                    tcp-established;
                }
                then accept;
            }
            term DENY_BY_DEFAULT {
                then {
                    syslog;
                    discard;
                }
            }
        }
    }
}


Note: Currently JUNOS has no method to filter option type within Hop-by-Hop header. Hence, all packets with the Hop-by-Hop header must be dropped. 


If the router is not configured to drop IPv6 packets containing a Hop-by-Hop header with invalid option type values, this is a finding.'
  desc 'fix', 'Configure the router to drop IPv6 packets containing a Hop-by-Hop header as shown in the example below.
Step 1: Configure a filter to block packets with a Hop-by-Hop header as shown in the example.

user@R1# edit firewall family inet6
user@R1# edit filter IPV6-INGRESS-FILTER
user@R1# set term HOP_BY_HOP_HEADER from next-header hop-by-hop
user@R1# set term HOP_BY_HOP_HEADER then discard syslog
user@R1# top

Step 2: Apply the filter inbound on all external IPv6-enabled interfaces.

user@R1# edit interfaces ge-0/0/0 unit 0 family inet6
user@R1# set filter input IPV6-INGRESS-FILTER
user@R1# commit'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-36230r639648_chk'
  tag severity: 'medium'
  tag gid: 'V-233295'
  tag rid: 'SV-233295r604135_rule'
  tag stig_id: 'JUNI-RT-000383'
  tag gtitle: 'SRG-NET-000364-RTR-000202'
  tag fix_id: 'F-36199r639649_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
