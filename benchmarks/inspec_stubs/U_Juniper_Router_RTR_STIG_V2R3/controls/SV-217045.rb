control 'SV-217045' do
  title 'The Juniper out-of-band management (OOBM) gateway router must be configured to forward only authorized management traffic to the Network Operations Center (NOC).'
  desc 'The OOBM network is an IP network used exclusively for the transport of OAM&P data from the network being managed to the OSS components located at the NOC. Its design provides connectivity to each managed network device, enabling network management traffic to flow between the managed network elements and the NOC. This allows the use of paths separate from those used by the managed network.'
  desc 'check', 'This requirement is not applicable for the DoDIN Backbone.

Review the network topology diagram to determine connectivity between the managed network and the NOC. Review the OOBM gateway router configuration to validate the path that the management traffic traverses. Verify that only management traffic is forwarded through the OOBM interface or IPsec tunnel.

If an OOBM link is used, verify that the only authorized management traffic is transported to the NOC by reviewing the outbound filter applied to the OOBM interface as shown in the example below.

interfaces {
     description "OOBM Net";
    ge-1/1/0 {
        unit 0 {
            family inet {
                filter {
                    output MGMT_TRAFFIC;
                }
                address 10.2.22.2/24;
            }
        }
    }
…
…
…
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
                then accept;
            }
            term ALLOW_TACACS {
                from {
                    protocol tcp;
                    port tacacs;
                }
                then accept;
            }
            term ALLOW_NETFLOW {
                from {
                    protocol udp;
                    port [ 2055 9995 9996 ];
                }
                then accept;
            }
            term DENY_OTHER {
                then {
                    syslog;
                    discard;
                }
            }
        }
    }

If an IPsec tunnel is used, verify that the only authorized management traffic is transported to the NOC by reviewing the filter referencing the applicable security association as shown int example below.

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

If traffic other than authorized management traffic is permitted through the OOBM interface or IPsec tunnel, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DoDIN Backbone.

Configure filters to permit only authorized management traffic into IPsec tunnels or the OOBM interface used for forwarding management data as shown in the examples below.

OOBM Link
[edit firewall family inet]
set filter MGMT_TRAFFIC term ALLOW_SNMP from protocol udp port [snmp snmptrap]
set filter MGMT_TRAFFIC term ALLOW_SNMP then accept
set filter MGMT_TRAFFIC term ALLOW_TACACS from protocol tcp port tacacs
set filter MGMT_TRAFFIC term ALLOW_TACACS then accept
set filter MGMT_TRAFFIC term ALLOW_NETFLOW from protocol udp port [2055 9995 9996]
set filter MGMT_TRAFFIC term ALLOW_NETFLOW then accept
set filter MGMT_TRAFFIC term DENY_OTHER then syslog discard

[edit interfaces ge-1/1/0  unit 0 family inet]
set filter output MGMT_TRAFFIC

IPsec Tunnel
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
  tag check_id: 'C-18274r297003_chk'
  tag severity: 'medium'
  tag gid: 'V-217045'
  tag rid: 'SV-217045r604135_rule'
  tag stig_id: 'JUNI-RT-000400'
  tag gtitle: 'SRG-NET-000205-RTR-000010'
  tag fix_id: 'F-18272r297004_fix'
  tag 'documentable'
  tag legacy: ['SV-101085', 'V-90875']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
