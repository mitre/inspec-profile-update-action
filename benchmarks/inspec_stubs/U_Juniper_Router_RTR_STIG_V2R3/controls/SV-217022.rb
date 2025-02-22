control 'SV-217022' do
  title 'The Juniper router must be configured to have Internet Control Message Protocol (ICMP) unreachable messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Host unreachable ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'Review the firewall hierarchy configuration to verify that all packets that are not permitted are silently dropped using the discard parameter as shown in the configuration example below.

firewall {
    family inet {
        …
        …
        …
        }
        filter FILTER_INBOUND {
            term ALLOW_XYZ {
                from {
                    protocol xyz;
                }
                then accept;
            }
            …
            …
            …
            }
            term DENY_BY_DEFAULT {
                then {
                    log;
                    discard;
                }
            }
        }
    }

If ICMP unreachable notifications are sent for packets that are dropped, this is a finding.'
  desc 'fix', '[edit firewall family inet]
set filter FILTER_INBOUND term DENY_BY_DEFAULT then log discard'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18251r296934_chk'
  tag severity: 'medium'
  tag gid: 'V-217022'
  tag rid: 'SV-217022r604135_rule'
  tag stig_id: 'JUNI-RT-000170'
  tag gtitle: 'SRG-NET-000362-RTR-000113'
  tag fix_id: 'F-18249r296935_fix'
  tag 'documentable'
  tag legacy: ['SV-101039', 'V-90829']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
