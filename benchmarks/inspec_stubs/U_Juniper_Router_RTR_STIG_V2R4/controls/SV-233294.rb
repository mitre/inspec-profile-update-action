control 'SV-233294' do
  title 'The Juniper perimeter router must be configured drop IPv6 packets with a Routing Header type 0, 1, or 3255.'
  desc 'The routing header can be used maliciously to send a packet through a path where less robust security is in place, rather than through the presumably preferred path of routing protocols. Use of the routing extension header has few legitimate uses other than as implemented by Mobile IPv6. 

The Type 0 Routing Header (RFC 5095) is dangerous because it allows attackers to spoof source addresses and obtain traffic in response, rather than the real owner of the address. Secondly, a packet with an allowed destination address could be sent through a Firewall using the Routing Header functionality, only to bounce to a different node once inside. The Type 1 Routing Header is defined by a specification called "Nimrod Routing", a discontinued project funded by DARPA. Assuming that most implementations will not recognize the Type 1 Routing Header, it must be dropped. The Type 3–255 Routing Header values in the routing type field are currently undefined and should be dropped inbound and outbound.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone. 

Review the router configuration to determine if it is configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255.

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

Step 2: Verify that the IPV6 filter blocks all packets with a routing header as shown in the example below.

firewall {
    family inet6 {
        filter IPV6-INGRESS-FILTER {
            term ROUTING_HEADER {
                from {
                    next-header routing;
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

Note: Currently JUNOS has no method to filter option type within a routing header. Hence, all packets with a routing header must be dropped. 


If the router is not configured to drop IPv6 packets containing a Routing Header of type 0, 1, or 3-255, this is a finding.'
  desc 'fix', 'Step 1: Configure a filter to block packets with a routing header as shown in the example.

user@R1# edit firewall family inet6
user@R1# edit filter IPV6-INGRESS-FILTER
user@R1# set term ROUTING_HEADER from next-header routing
user@R1# set term ROUTING_HEADER then discard syslog
user@R1# top

Step 2: Apply the filter inbound on all external IPv6-enabled interfaces.

user@R1# edit interfaces ge-0/0/0 unit 0 family inet6
user@R1# set filter input IPV6-INGRESS-FILTER
user@R1# commit'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-36229r639645_chk'
  tag severity: 'medium'
  tag gid: 'V-233294'
  tag rid: 'SV-233294r604135_rule'
  tag stig_id: 'JUNI-RT-000382'
  tag gtitle: 'SRG-NET-000364-RTR-000201'
  tag fix_id: 'F-36197r639646_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
