control 'SV-217078' do
  title 'The Juniper PE router must be configured to ignore or block all packets with any IP options.'
  desc 'Packets with IP options are not fast switched and therefore must be punted to the router processor. Hackers who initiate denial-of-service (DoS) attacks on routers commonly send large streams of packets with IP options. Dropping the packets with IP options reduces the load of IP options packets on the router. The end result is a reduction in the effects of the DoS attack on the router and on downstream routers.'
  desc 'check', 'Review the router configuration to determine if it will block all packets with IP options.

firewall {
    family inet {
        filter INGRESS_FILTER {
            term BLOCK_TO_CORE {
                from {
                    destination-address {
                        x.x.x.x/8;
                    }
                }
                then {
                    log;
                    discard;
                }
            }
            term BLOCK_IP_OPTIONS {
                from {
                    ip-options any;
                }
                then {
                    discard;
                }
            }
            term ALLOW_TRANSIT_TRAFFIC {
                then accept;
            }
        }
    }

If the router is not configured to drop all packets with IP options, this is a finding.'
  desc 'fix', 'Configure the router to drop all packets with IP options.

[edit firewall family inet filter INGRESS_FILTER]
set term BLOCK_IP_OPTIONS from ip-options any
set term BLOCK_IP_OPTIONS then discard
insert term BLOCK_IP_OPTIONS before term ALLOW_TRANSIT_TRAFFIC'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18307r297102_chk'
  tag severity: 'medium'
  tag gid: 'V-217078'
  tag rid: 'SV-217078r639663_rule'
  tag stig_id: 'JUNI-RT-000730'
  tag gtitle: 'SRG-NET-000205-RTR-000016'
  tag fix_id: 'F-18305r297103_fix'
  tag 'documentable'
  tag legacy: ['V-90937', 'SV-101147']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
