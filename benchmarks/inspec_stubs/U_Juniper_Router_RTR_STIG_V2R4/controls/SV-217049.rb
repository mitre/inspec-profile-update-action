control 'SV-217049' do
  title 'The Juniper router must be configured to only permit management traffic that ingresses and egresses the OOBM interface.'
  desc 'The OOBM access switch will connect to the management interface of the managed network elements. The management interface can be a true OOBM interface or a standard interface functioning as the management interface. In either case, the management interface of the managed network element will be directly connected to the OOBM network.

An OOBM interface does not forward transit traffic, thereby providing complete separation of production and management traffic. Since all management traffic is immediately forwarded into the management network, it is not exposed to possible tampering. The separation also ensures that congestion or failures in the managed network do not affect the management of the device. If the device does not have an OOBM port, the interface functioning as the management interface must be configured so that management traffic does not leak into the managed network and that production traffic does not leak into the management network.'
  desc 'check', 'Verify that the managed interface has an inbound and outbound filter configured. 

interfaces {
    …
    …
    …
    ge-0/0/0 {
        description "OOBM Network";
        unit 0 {
            family inet {
                filter {
                    input OOBM_INBOUND;
                    output OOBM_OUTBOUND;
                }
                address 10.2.14.1/24;
            }
        }
    }

Verify that the ingress filter only allows management and ICMP traffic. 

firewall {
    family inet {
        …
        …
        …
        filter OOBM_INBOUND {
            term ALLOW_SNMP {
                from {
                    protocol udp;
                    port snmp;
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
            term ALLOW_ICMP {
                from {
                    protocol icmp;
                }
                then accept;
            }
            term ALLOW_SSH {
                from {
                    protocol tcp;
                    port ssh;
                }
                then accept;
            }
            term ALLOW_NTP {
                from {
                    protocol tcp;
                    port ntp;
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
}

Verify that the ingress filter only allows management and ICMP traffic. 

firewall {
    family inet {
        …
        …
        …
        filter OOBM_OUTBOUND {
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
            term ALLOW_SSH {
                from {
                    protocol tcp;
                    port ssh;
                }
                then accept;
            }
            term ALLOW_NTP {
                from {
                    protocol udp;
                    port ntp;
                }
                then accept;
            }
            term ALLOW_SYSLOG {
                from {
                    protocol udp;
                    port syslog;
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
}

Caveat: If the management interface is a true OOBM interface, this requirement is not applicable.

If the router does not restrict traffic that ingresses and egresses the management interface, this is a finding.'
  desc 'fix', 'If the management interface is not a dedicated OOBM interface, it must be configured with both an ingress and egress filter.

Configure an inbound filter a shown in the example below.

[edit firewall family inet]
set filter OOBM_INBOUND term ALLOW_SNMP from protocol udp port snmp
set filter OOBM_INBOUND term ALLOW_SNMP then accept
set filter OOBM_INBOUND term ALLOW_TACACS from protocol tcp port tacacs
set filter OOBM_INBOUND term ALLOW_TACACS then accept
set filter OOBM_INBOUND term ALLOW_SSH from protocol tcp port ssh
set filter OOBM_INBOUND term ALLOW_SSH then accept
set filter OOBM_INBOUND term ALLOW_NTP from protocol udp port ntp
set filter OOBM_INBOUND term ALLOW_NTP then accept
set filter OOBM_INBOUND term ALLOW_ICMP from protocol icmp
set filter OOBM_INBOUND term ALLOW_ICMP then accept
set filter OOBM_INBOUND term DENY_OTHER then syslog discard

Configure an outbound filter a shown in the example below.

set filter OOBM_OUTBOUND term ALLOW_SNMP from protocol udp port [snmp snmptrap]
set filter OOBM_OUTBOUND term ALLOW_SNMP then accept
set filter OOBM_OUTBOUND term ALLOW_TACACS from protocol tcp port tacacs
set filter OOBM_OUTBOUND term ALLOW_TACACS then accept
set filter OOBM_OUTBOUND term ALLOW_SSH from protocol tcp port ssh
set filter OOBM_OUTBOUND term ALLOW_SSH then accept
set filter OOBM_OUTBOUND term ALLOW_NTP from protocol udp port ntp
set filter OOBM_OUTBOUND term ALLOW_NTP then accept
set filter OOBM_OUTBOUND term ALLOW_SYSLOG from protocol udp port 
set filter OOBM_OUTBOUND term ALLOW_SYSLOG then accept
set filter OOBM_OUTBOUND term ALLOW_NETFLOW from protocol udp port [2055 9995 9996]
set filter OOBM_OUTBOUND term ALLOW_NETFLOW then accept
set filter OOBM_OUTBOUND term DENY_OTHER then syslog discard

Apply the filters to the OOBM interfaces.

[edit interfaces ge-0/0/0  unit 0 family inet]
set filter input OOBM_INBOUND
set filter output OOBM_OUTBOUND'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18278r297015_chk'
  tag severity: 'medium'
  tag gid: 'V-217049'
  tag rid: 'SV-217049r604135_rule'
  tag stig_id: 'JUNI-RT-000440'
  tag gtitle: 'SRG-NET-000205-RTR-000012'
  tag fix_id: 'F-18276r297016_fix'
  tag 'documentable'
  tag legacy: ['SV-101093', 'V-90883']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
