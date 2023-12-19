control 'SV-217050' do
  title 'The Juniper router providing connectivity to the NOC must be configured to forward all in-band management traffic via an IPsec tunnel.'
  desc 'When the production network is managed in-band, the management network could be housed at a NOC that is located remotely at single or multiple interconnected sites. NOC interconnectivity, as well as connectivity between the NOC and the managed network, must be enabled using IPsec tunnels to provide the separation and integrity of the managed traffic.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Verify that all traffic from the managed network to the management network and vice-versa is secured via IPsec tunnel.

Review the security association within the IPsec configuration to be used for encapsulating the management traffic and verify that it is in tunnel mode. Also note the security association to be used.

security {
    ipsec {
        proposal IPSEC_PHASE2_PROPOSAL {
            protocol esp;
            authentication-algorithm hmac-sha1-96;
            encryption-algorithm aes-128-cbc;
        }
        policy IPSEC_POLICY {
            perfect-forward-secrecy {
                keys group14;
            }
            proposals IPSEC_PHASE2_PROPOSAL;
        }
        security-association IPSEC-SA_XYZ {
            description "For XYZ";
            mode transport;
            manual {
                direction bidirectional {
                    protocol ah;
                    spi 256;
                    authentication {
                        algorithm hmac-sha1-96;
                        key ascii-text "$8$oPJjH.P5F69mSHqPQn6u0RhSreW-dsZGi8XYoZDmP"; ## SECRET-DATA
                    }
                }
            }
        }
        security-association IPSEC_SA_MGMT {
            description "IPsec Tunnel for Mgmt Traffic";
            mode tunnel;
            dynamic {
                ipsec-policy IPSEC_POLICY;
            }
        }
    }
    ike {
        proposal IKE_PHASE1_PROPOSAL {
            authentication-method pre-shared-keys;
            dh-group group14;
            authentication-algorithm sha-256;
            encryption-algorithm aes-128-cbc;
        }
        policy 10.1.25.2 {
            mode main;
            proposals IKE_PHASE1_PROPOSAL;
            pre-shared-key ascii-text "$8$J4UDkCA01IcHqEy"; ## SECRET-DATA
        }
    }

Verify there is a filter to direct the management traffic to the IPsec tunnel by verifying the name of the IPsec SA referenced in the then statement as shown in the example below.

firewall {
    family inet {
        …
        …
        …
       filter MGMT_TRAFFIC {
            term ALLOW_SNMP {
                from {
                    protocol udp;
                    port [ snmp snmptrap ];
                }
                then ipsec-sa IPSEC_SA_MGMT;
            }
            term ALLOW_TACACS {
                from {
                    protocol tcp;
                    port tacacs;
                }
                then ipsec-sa IPSEC_SA_MGMT;
            }
            term ALLOW_NETFLOW {
                from {
                    protocol udp;
                    port [ 2055 9995 9996 ];
                }
                then ipsec-sa IPSEC_SA_MGMT;
            }
            term OTHER {
                then accept;
            }
        }
    }

If the management traffic is not secured via IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Ensure that all traffic from the managed network to the management network is secured via IPsec tunnel as shown in the configuration examples below.

Configure an IPsec tunnel to be used to transport the management traffic.

[edit security]
set ike proposal IKE_PHASE1_PROPOSAL authentication-method pre-shared-keys
set ike proposal IKE_PHASE1_PROPOSAL authentication-algorithm sha-256
set ike proposal IKE_PHASE1_PROPOSAL dh-group group14
set ike proposal IKE_PHASE1_PROPOSAL encryption-algorithm aes-128-cbc
set ike policy 10.1.25.2 proposals IKE_PHASE1_PROPOSAL
set ike policy 10.1.25.2 mode main
set ike policy 10.1.25.2 pre-shared-key ascii-text xxxxxxxxx
set ipsec proposal IPSEC_PHASE2_PROPOSAL protocol esp
set ipsec proposal IPSEC_PHASE2_PROPOSAL authentication-algorithm hmac-sha1-96
set ipsec proposal IPSEC_PHASE2_PROPOSAL encryption-algorithm aes-128-cbc
set policy IPSEC_POLICY perfect-forward-secrecy keys group14
set policy IPSEC_POLICY proposals xxxxx
set ipsec security-association IPSEC_SA_MGMT mode tunnel
set ipsec security-association IPSEC_SA_MGMT dynamic ipsec-policy IPSEC_POLICY

Configure a filter that will select which traffic to be forwarded via the IPsec tunnel by specifying the security association bound to the tunnel.

[edit firewall family inet]
set filter MGMT_TRAFFIC term ALLOW_SNMP from protocol udp port [snmp snmptrap]
set filter MGMT_TRAFFIC term ALLOW_SNMP then ipsec-sa IPSEC_SA_MGMT
set filter MGMT_TRAFFIC term ALLOW_TACACS from protocol tcp port tacacs
set filter MGMT_TRAFFIC term ALLOW_TACACS then ipsec-sa IPSEC_SA_MGMT
set filter MGMT_TRAFFIC term ALLOW_NETFLOW from protocol udp port [2055 9995 9996]
set filter MGMT_TRAFFIC term ALLOW_NETFLOW then ipsec-sa IPSEC_SA_MGMT
set filter MGMT_TRAFFIC term OTHER then accept'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18279r297018_chk'
  tag severity: 'medium'
  tag gid: 'V-217050'
  tag rid: 'SV-217050r604135_rule'
  tag stig_id: 'JUNI-RT-000450'
  tag gtitle: 'SRG-NET-000205-RTR-000013'
  tag fix_id: 'F-18277r297019_fix'
  tag 'documentable'
  tag legacy: ['SV-101095', 'V-90885']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
