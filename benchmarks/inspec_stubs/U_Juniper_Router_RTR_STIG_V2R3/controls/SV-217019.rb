control 'SV-217019' do
  title 'The Juniper router must be configured to restrict traffic destined to itself.'
  desc 'The Routing Engine handles traffic destined to the router—the key component used to build forwarding paths and is instrumental with all network management functions. Hence, any disruption or DoS attack to the Routing Engine can result in mission critical network outages.'
  desc 'check', 'Review the filter for the router’s receive path and verify that it will only allow specific management plane traffic from specific sources.

Verify filter has been configured as shown in the example below.

firewall {
    family inet {
         …
        …
        …
        }
        filter DESTINED_TO_RE {
            term ALLOW_OSPF {
                from {
                    protocol ospf;
                }
                then accept;
            }
            term ALLOW_BGP {
                from {
                    source-address {
                        11.1.12.1/32;
                        11.1.23.3/32;
                        11.1.25.5/32;
                    }
                    protocol tcp;
                    port bgp;
                }
            }
            term FILTER_TCP {
                from {
                    destination-address {
                        11.1.12.0/24;
                    }
                    protocol tcp;
                    destination-port [ ssh tacacs telnet ];
                }
                then accept;
            }
            term FILTER_UDP {
                from {
                    destination-address {
                        11.1.12.0/24;
                    }
                    protocol udp;
                    destination-port [ntp snmp ];
                }
                then accept;
            }
            term ICMP_ANY {
                from {
                    protocol icmp;
                }
                then accept;
            }
            term DENY_BY_DEFAULT {
                then {
                    log;
                    discard;
                }
            }
        }
    }

Verify that the input filter has been applied to loopback interface as shown in the example below.
    
interfaces {
…
…
…
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input-list [ DESTINED_TO_RE CoPP_Policy ];
                }
                address 2.2.2.2/32;
            }
         }
    }
}

If the router is not configured with a receive-path filter to restrict traffic destined to itself, this is a finding'
  desc 'fix', 'Configure the router’s receive path filters to restrict traffic destined to the router.

Configure a filter to define what traffic should be received by the Routing Engine.

[edit firewall family inet]
set filter DESTINED_TO_RP term FILTER_TCP from destination-address 11.1.12.0/24  
set filter DESTINED_TO_RP term FILTER_TCP from protocol tcp destination-port ssh
set filter DESTINED_TO_RP term FILTER_TCP from protocol tcp destination-port tacacs
set filter DESTINED_TO_RP term FILTER_TCP then accept
set filter DESTINED_TO_RP term FILTER_UDP from destination-address 11.1.12.0/24  
set filter DESTINED_TO_RP term FILTER_UDP from protocol udp destination-port ntp
set filter DESTINED_TO_RP term FILTER_UDP from protocol udp destination-port snmp
set filter DESTINED_TO_RP term FILTER_UDP then accept
set filter DESTINED_TO_RP term ICMP_ANY from protocol icmp 
set filter DESTINED_TO_RP term ICMP_ANY from protocol icmp then accept
set filter DESTINED_TO_RP term DENY_BY_DEFAULT then log discard

Apply the filter to the loopback interface.

[edit interfaces lo0 unit 0 family inet] 
set filter input-list DESTINED_TO_RP.'
  impact 0.7
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18248r296925_chk'
  tag severity: 'high'
  tag gid: 'V-217019'
  tag rid: 'SV-217019r604135_rule'
  tag stig_id: 'JUNI-RT-000130'
  tag gtitle: 'SRG-NET-000205-RTR-000001'
  tag fix_id: 'F-18246r296926_fix'
  tag 'documentable'
  tag legacy: ['SV-101033', 'V-90823']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
