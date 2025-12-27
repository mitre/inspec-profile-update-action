control 'SV-217018' do
  title 'The Juniper router must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.'
  desc 'The Routing Engine (RE) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the RP or the control and management planes can result in mission-critical network outages.

A DoS attack targeting the RE can result in excessive CPU and memory utilization. To maintain network stability and RP security, the router must be able to handle specific control plane and management plane traffic that is destined to the RE. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grows. Control plane policing increases the security of routers and multilayer switches by protecting the RE from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Determine whether control plane protection has been implemented on the router.

Verify that a CoPP policy has been configured that classifies traffic types into levels of importance.

firewall {
    family inet {
…
…
…
    }
    filter CoPP_Policy {
        term CRITICAL {
            from {
                protocol [ ospf pim tcp ];
                source-port bgp;
                destination-port bgp;
            }
            then policer CRITICAL_POLICER;
        }
        term IMPORTANT {
            from {
                protocol [ tcp udp ];
                destination-port [ ssh tacacs snmp ntp ];
            }
            then {
                policer IMPORTANT_POLICER; 
            }
        }
        term NORMAL {
            from {
                protocol icmp;
                icmp-type [ echo-reply echo-request ];
                icmp-code [ port-unreachable ttl-eq-zero-during-transit ];
            }
            then policer NORMAL_POLICER;
        }
        term UNDESIRABLE {
            from {
                protocol udp;
            }
            then policer UNDESIRABLE_POLICER;
        }
        term ALL-OTHER {
            from {
                address {
                    0.0.0.0/0;
                }
            }
            then policer ALL-OTHER_POLICER;
        }
    }
}

Verify that policers have been configured to rate limit traffic types.

firewall {
    family inet {
…
…
…
    }
    policer CRITICAL_POLICER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 3m;
            burst-size-limit 4k;
        }
        then discard;
    }
    policer IMPORTANT_POLICER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 400k;
            burst-size-limit 1500;
        }
        then discard;
    }
    policer NORMAL_POLICER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 55k;
            burst-size-limit 1500;
        }
        then discard;
    }
    policer UNDESIRABLE_POLICER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 32k;
            burst-size-limit 1500;
        }
        then discard;
    }
    policer ALL-OTHER_POLICER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 40k;
            burst-size-limit 1500;
        }
        then discard;
    }

Verify that the CoPP policy has been applied to the loopback interface as shown in the example below.

interfaces {
…
…
…
    lo0 {
        unit 0 {
            family inet {
                filter {
                    input CoPP_Policy;
                }
                address 2.2.2.2/32;
            }
         }
    }
}

Note: Several Juniper router platforms provide a DDoS Protection feature that is configured at the system hierarchy via set ddos-protection commands.

If the router does not have control plane protection implemented, this is a finding.'
  desc 'fix', 'Implement control plane protection by classifying traffic types based on importance and rate limit the traffic accordingly as shown in the example below.

Create filters for critical, important, normal, and undesirable traffic.

set firewall filter CoPP_Policy term CRITICAL from protocol ospf
set firewall filter CoPP_Policy term CRITICAL from protocol pim
set firewall filter CoPP_Policy term CRITICAL from protocol tcp destination-port bgp
set firewall filter CoPP_Policy term CRITICAL from protocol tcp source-port bgp
set firewall filter CoPP_Policy term CRITICAL then policer CRITICAL_POLICER

set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ssh
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port tacacs
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port snmp
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ntp
set firewall filter CoPP_Policy term IMPORTANT then policer IMPORTANT_POLICER

set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-code ttl-eq-zero-during-transit
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-code port-unreachable
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-type echo-reply
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-type echo-request
set firewall filter CoPP_Policy term NORMAL then policer NORMAL_POLICER

set firewall filter CoPP_Policy term UNDESIRABLE from protocol udp  
set firewall filter CoPP_Policy term UNDESIRABLE then policer UNDESIRABLE_POLICER

set firewall filter CoPP_Policy term ALL-OTHER from address 0.0.0.0/0
set firewall filter CoPP_Policy term ALL-OTHER then policer ALL-OTHER_POLICER

Create policers for each traffic type to limit bandwidth.

set firewall policer CRITICAL_POLICER filter-specific
set firewall policer CRITICAL_POLICER if-exceeding bandwidth-limit 3000000 burst-size-limit 4000
set firewall policer CRITICAL_POLICER then discard

set firewall policer IMPORTANT_POLICER filter-specific
set firewall policer IMPORTANT_POLICER if-exceeding bandwidth-limit 400000 burst-size-limit 1500
set firewall policer IMPORTANT_POLICER then discard

set firewall policer NORMAL_POLICER filter-specific
set firewall policer NORMAL_POLICER if-exceeding bandwidth-limit 55000 burst-size-limit 150000
set firewall policer NORMAL_POLICER then discard

set firewall policer UNDESIRABLE_POLICER filter-specific
set firewall policer UNDESIRABLE_POLICER if-exceeding bandwidth-limit 32000 burst-size-limit 1500
set firewall policer UNDESIRABLE_POLICER then discard

set firewall policer ALL-OTHER_POLICER filter-specific
set firewall policer ALL-OTHER_POLICER if-exceeding bandwidth-limit 40000 burst-size-limit 1500
set firewall policer ALL-OTHER_POLICER then discard

Apply the CoPP policy to the loopback interface.

set interface lo0 unit 0 family inet filter input CoPP_Policy

Note: Several Juniper router platforms provide a DDoS Protection feature that is configured at the system hierarchy via set ddos-protection commands.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18247r296922_chk'
  tag severity: 'medium'
  tag gid: 'V-217018'
  tag rid: 'SV-217018r604135_rule'
  tag stig_id: 'JUNI-RT-000120'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-18245r296923_fix'
  tag 'documentable'
  tag legacy: ['SV-101031', 'V-90821']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
