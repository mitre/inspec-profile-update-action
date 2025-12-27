control 'SV-217044' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to transport management traffic to the Network Operations Center (NOC) via dedicated circuit, MPLS/VPN service, or IPsec tunnel.'
  desc 'Using dedicated paths, the OOBM backbone connects the OOBM gateway routers located at the edge of the managed network and at the NOC. Dedicated links can be deployed using provisioned circuits or MPLS Layer 2 and Layer 3 VPN services or implementing a secured path with gateway-to-gateway IPsec tunnels. The tunnel mode ensures that the management traffic will be logically separated from any other traffic traversing the same path.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path and interface that the management traffic traverses. If an IPsec tunnel is used to transport the management traffic between the NOC and the managed network, review the configuration following the steps below.

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

If management traffic is not transported between the managed network and the NOC via dedicated circuit, MPLS/VPN service, or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Ensure that a dedicated circuit, MPLS/VPN service, or IPsec tunnel is deployed to transport management traffic between the managed network and the NOC.  If an IPsec tunnel is to be used, the steps below can be used as a guideline.

Configure an IPsec tunnel using commands similar to the example below.

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
set ipsec security-association IPSEC_SA_MGMT mode tunnel
set ipsec security-association IPSEC_SA_MGMT dynamic ipsec-policy IPSEC_POLICY

Configure a filter to define the management traffic to be forwarded into the IPsec tunnel.

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
  tag check_id: 'C-18273r297000_chk'
  tag severity: 'medium'
  tag gid: 'V-217044'
  tag rid: 'SV-217044r604135_rule'
  tag stig_id: 'JUNI-RT-000390'
  tag gtitle: 'SRG-NET-000205-RTR-000009'
  tag fix_id: 'F-18271r297001_fix'
  tag 'documentable'
  tag legacy: ['SV-101083', 'V-90873']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
