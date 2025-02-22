control 'SV-217342' do
  title 'The Juniper router must be configured to protect against known types of Denial of Service (DoS) attacks by employing organization-defined security safeguards.'
  desc 'DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity.

This requirement addresses the configuration of network devices to mitigate the impact of DoS attacks that have occurred or are ongoing on device availability. For each network device, known and potential DoS attacks must be identified and solutions for each type implemented. A variety of technologies exist to limit or, in some cases, eliminate the effects of DoS attacks (e.g., limiting processes or restricting the number of sessions the device opens at one time). Employing increased capacity and bandwidth, combined with service redundancy, may reduce the susceptibility to some DoS attacks.

The security safeguards cannot be defined at the DoD level because they vary according to the capabilities of the individual network devices and the security controls applied on the adjacent networks (for example, firewalls performing packet filtering to block DoS attacks).'
  desc 'check', 'Review the router configuration to verify that it is compliant with this requirement. 

Step 1: Verify that the loopback interfaces has been configured with an input filter. The example below defined a control plane policing (CoPP) filter named CoPP_Policy.

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
                address 5.5.5.5/32;
            }
        }
    }
}

Step 2: Verify that the filter will protect against DoS attacks.

firewall {
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
            then policer CRITICAL;
        }
        term IMPORTANT {
            from {
                source-address {
                    10.1.1.0/24;
                }
                protocol tcp;
                destination-port [ ssh snmp ntp ];
            }
            then {
                policer IMPORTANT;
                discard;
            }
        }
        term NORMAL {
            from {
                protocol icmp;
                icmp-type [ echo-reply echo-request ];
                icmp-code [ ttl-eq-zero-during-transit port-unreachable ];
            }
            then policer NORMAL;
        }
        term UNDESIRABLE {
            from {
                protocol udp;
                destination-port 1434;
            }
            then policer UNDESIRABLE;
        }
        term ALL-OTHER {
            from {
                address {
                    0.0.0.0/0;
                }
            }
            then policer ALL-OTHER;
        }
    }
}

Step 3: verify that policers configured will restrict bandwidth based on traffic types as shown in the example below.

firewall {
    …
    …
    …
    }
    policer CRITICAL {
        filter-specific;
        if-exceeding {
            bandwidth-limit 4m;
            burst-size-limit 1500;
        }
        then discard;
    }
    policer IMPORTANT {
        filter-specific;
        if-exceeding {
            bandwidth-limit 512k;
            burst-size-limit 16k;
        }
        then discard;
    }
    policer NORMAL {
        filter-specific;
        if-exceeding {
            bandwidth-limit 64k;
            burst-size-limit 2k;
        }
        then discard;
    }
    policer UNDESIRABLE {
        filter-specific;
        if-exceeding {
            bandwidth-limit 32k;
            burst-size-limit 1500;
        }
        then discard;
    }
    policer ALL-OTHER {
        filter-specific;
        if-exceeding {
            bandwidth-limit 32k;
            burst-size-limit 1500;
        }
        then discard;
    }

If the router is not configured to protect against known types of DoS attacks by employing organization-defined security safeguards, this is a finding.'
  desc 'fix', 'Configure the router protect against known types of DoS attacks on the route processor. Implementing a CoPP policy as shown in the example below is a best practice method.

Step 1: Configure policers for specific traffic types.

set firewall policer CRITICAL filter-specific
set firewall policer CRITICAL if-exceeding bandwidth-limit 4000000 burst-size-limit 1500
set firewall policer CRITICAL then discard
set firewall policer IMPORTANT filter-specific
set firewall policer IMPORTANT if-exceeding bandwidth-limit 512000 burst-size-limit 16000
set firewall policer IMPORTANT then discard
set firewall policer NORMAL filter-specific
set firewall policer NORMAL if-exceeding bandwidth-limit 64000 burst-size-limit 2000
set firewall policer NORMAL then discard
set firewall policer UNDESIRABLE filter-specific
set firewall policer UNDESIRABLE if-exceeding bandwidth-limit 32000 burst-size-limit 1500
set firewall policer UNDESIRABLE then discard
set firewall policer ALL-OTHER filter-specific
set firewall policer ALL-OTHER if-exceeding bandwidth-limit 32000 burst-size-limit 1500
set firewall policer ALL-OTHER then discard

Step 2: Configure the CoPP filter by applying policers to the appropriate traffic types.

set firewall filter CoPP_Policy term CRITICAL from protocol ospf
set firewall filter CoPP_Policy term CRITICAL from protocol pim
set firewall filter CoPP_Policy term CRITICAL from protocol tcp destination-port bgp
set firewall filter CoPP_Policy term CRITICAL from protocol tcp source-port bgp
set firewall filter CoPP_Policy term CRITICAL then policer CRITICAL
set firewall filter CoPP_Policy term IMPORTANT from source-address 10.1.1.0/24
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ssh
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port snmp
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ntp
set firewall filter CoPP_Policy term IMPORTANT then policer IMPORTANT
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ssh
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port snmp
set firewall filter CoPP_Policy term IMPORTANT from protocol tcp destination-port ntp
set firewall filter CoPP_Policy term IMPORTANT then discard
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-code ttl-eq-zero-during-transit
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-code port-unreachable
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-type echo-reply
set firewall filter CoPP_Policy term NORMAL from protocol icmp icmp-type echo-request
set firewall filter CoPP_Policy term NORMAL then policer NORMAL
set firewall filter CoPP_Policy term UNDESIRABLE from protocol udp destination-port 1434
set firewall filter CoPP_Policy term UNDESIRABLE then policer UNDESIRABLE
set firewall filter CoPP_Policy term ALL-OTHER from address 0.0.0.0/0
set firewall filter CoPP_Policy term ALL-OTHER then policer ALL-OTHER

Step 3: Apply the CoPP filter to the loopback interface.

set interface lo0 unit 0 family inet filter input CoPP_Policy'
  impact 0.5
  ref 'DPMS Target Juniper Router NDM'
  tag check_id: 'C-18569r296604_chk'
  tag severity: 'medium'
  tag gid: 'V-217342'
  tag rid: 'SV-217342r879806_rule'
  tag stig_id: 'JUNI-ND-001210'
  tag gtitle: 'SRG-APP-000435-NDM-000315'
  tag fix_id: 'F-18567r296605_fix'
  tag 'documentable'
  tag legacy: ['SV-101273', 'V-91173']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
