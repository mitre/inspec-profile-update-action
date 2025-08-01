control 'SV-217043' do
  title 'The Juniper perimeter router must be configured to block all outbound management traffic.'
  desc 'For in-band management, the management network must have its own subnet in order to enforce control and access boundaries provided by Layer 3 network nodes, such as routers and firewalls. Management traffic between the managed network elements and the management network is routed via the same links and nodes as that used for production or operational traffic. Safeguards must be implemented to ensure that the management traffic does not leak past the perimeter of the managed network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

The perimeter router of the managed network must be configured with an outbound filter on the egress interface to block all management traffic as shown in the example below.

Verify that the router has been configured with an outbound filter as shown in the example below.

interfaces {
     description "NIPRNet";
    ge-0/0/0 {
        unit 0 {
            family inet {
                no-redirects;
                filter {
                    output OUTBOUND_FILTER;
                }
                address 10.1.12.2/24;
            }
        }
    }

Verify that the outbound filter discard or rejects management traffic as shown in the example below.

firewall {
    family inet {
        …
        …
        …
        }
        filter OUTBOUND_FILTER {
            term BLOCK_TACACS {
                from {
                    protocol tcp;
                    port tacacs;
                }
                then {
                    syslog;
                    discard;
                }
            }
            term BLOCK_SNMP {
                from {
                    protocol udp;
                    port [ snmp snmptrap ];
                }
                then {
                    syslog;
                    discard;
                }
            }
            term BLOCK_NETFLOW {
                from {
                    protocol udp;
                    port [ 2055 9995 9996 ];
                }
            }
            term ALLOW_OTHER {
                then accept;
            }
        }
    }

If management traffic is not blocked at the perimeter, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure the perimeter router of the managed network with an outbound filter on the egress interface to block all management traffic.

Configure a filter to block egress management traffic.

[edit firewall family inet]
Set filter OUTBOUND_FILTER term BLOCK_TACACS from protocol tcp port tacacs
Set filter OUTBOUND_FILTER term BLOCK_TACACS then syslog discard
Set filter OUTBOUND_FILTER term BLOCK_SNMP from protocol udp port [snmp snmptrap]
Set filter OUTBOUND_FILTER term BLOCK_SNMP then syslog discard
set filter OUTBOUND_FILTER term BLOCK_NETFLOW from protocol udp port [2055 9995 9996]
set filter OUTBOUND_FILTER term BLOCK_NETFLOW then syslog discard 

Configure the external interfaces with the outbound filter.

[edit interfaces ge-0/0/0  unit 0 family inet]
set filter output OUTBOUND_FILTER'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18272r296997_chk'
  tag severity: 'medium'
  tag gid: 'V-217043'
  tag rid: 'SV-217043r604135_rule'
  tag stig_id: 'JUNI-RT-000380'
  tag gtitle: 'SRG-NET-000364-RTR-000113'
  tag fix_id: 'F-18270r296998_fix'
  tag 'documentable'
  tag legacy: ['SV-101081', 'V-90871']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
