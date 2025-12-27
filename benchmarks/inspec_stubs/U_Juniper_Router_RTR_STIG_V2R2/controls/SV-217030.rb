control 'SV-217030' do
  title 'The Juniper perimeter router must be configured to enforce approved authorizations for controlling the flow of information between interconnected networks in accordance with applicable policy.'
  desc 'Information flow control regulates authorized information to travel within a network and between interconnected networks. Controlling the flow of network traffic is critical so it does not introduce any unacceptable risk to the network infrastructure or data. An example of a flow control restriction is blocking outside traffic claiming to be from within the organization. For most routers, internal information flow control is a product of system design.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Review the router configuration to verify that filters are configured to allow or deny traffic for specific source and destination addresses as well as ports and protocols. In the example below, the router is peering BGP with DISN. ICMP echo and echo-reply packets are allowed for troubleshooting connectivity. WWW traffic is permitted inbound to the NIPRnet host-facing web server (x.12.1.22).

Step 1: Verify that external interface has an inbound filter configured as shown in the example below:

interfaces {
    ge-0/0/0 {
        unit 0 {
            family inet {
                filter {
                    input FILTER_INBOUND_TRAFFIC;
                }
                address x.1.12.2/30;
            }
        }
    }


Step 2: Verify that the inbound filter allows only traffic that is to be permitted into the network as shown in the example below:

firewall {
    family inet {
        filter FILTER_INBOUND_TRAFFIC {
            term TCP_ESTABLISHED {
                from {
                    tcp-established;
                }
                then accept;
            }
            term ALLOW_BGP {
                from {
                    source-address {
                        x.1.12.1/32;
                    }
                    protocol tcp;
                    destination-port bgp;
                }
                then accept;
            }
            term ALLOW_PING {
                from {
                    protocol icmp;
                    icmp-type [ echo-reply echo-request ];
                }
                then accept;
            }
            term ALLOW_WWW {
                from {
                    destination-address {
                       x.12.1.22/32;
                    }
                    protocol tcp;
                    destination-port http;
                }
                then accept;
            }
            term DENY_ALL_OTHER {
                then {
                    syslog;
                    reject;
                }
            }
        }
    }
}

If the router is not configured to enforce approved authorizations for controlling the flow of information within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

[edit firewall family inet]
set filter FILTER_INBOUND_TRAFFIC term TCP_ESTABLISHED from tcp-established
set filter FILTER_INBOUND_TRAFFIC term TCP_ESTABLISHED then accept
set filter FILTER_INBOUND_TRAFFIC term ALLOW_BGP from source-address x.1.12.1/32
set filter FILTER_INBOUND_TRAFFIC term ALLOW_BGP from protocol tcp
set filter FILTER_INBOUND_TRAFFIC term ALLOW_BGP from destination-port bgp
set filter FILTER_INBOUND_TRAFFIC term ALLOW_BGP then accept
set filter FILTER_INBOUND_TRAFFIC term ALLOW_PING from protocol icmp
set filter FILTER_INBOUND_TRAFFIC term ALLOW_PING from icmp-type echo-reply
set filter FILTER_INBOUND_TRAFFIC term ALLOW_PING from icmp-type echo-request
set filter FILTER_INBOUND_TRAFFIC term ALLOW_PING then accept
set filter FILTER_INBOUND_TRAFFIC term ALLOW_WWW from destination-address x.12.1.22/32
set filter FILTER_INBOUND_TRAFFIC term ALLOW_WWW from protocol tcp
set filter FILTER_INBOUND_TRAFFIC term ALLOW_WWW from destination-port http
set filter FILTER_INBOUND_TRAFFIC term ALLOW_WWW then accept
set filter FILTER_INBOUND_TRAFFIC term DENY_ALL_OTHER then syslog
set filter FILTER_INBOUND_TRAFFIC term DENY_ALL_OTHER then reject

Step 2: Apply the filter inbound on all applicable interfaces.

[edit interfaces ge-0/0/0 unit 0 family inet]
set filter input FILTER_INBOUND_TRAFFIC'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18259r296958_chk'
  tag severity: 'medium'
  tag gid: 'V-217030'
  tag rid: 'SV-217030r639663_rule'
  tag stig_id: 'JUNI-RT-000250'
  tag gtitle: 'SRG-NET-000019-RTR-000002'
  tag fix_id: 'F-18257r296959_fix'
  tag 'documentable'
  tag legacy: ['V-90845', 'SV-101055']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
