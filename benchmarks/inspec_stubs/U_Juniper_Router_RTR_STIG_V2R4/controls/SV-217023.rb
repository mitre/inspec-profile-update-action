control 'SV-217023' do
  title 'The Juniper router must be configured to have Internet Control Message Protocol (ICMP) mask reply messages disabled on all external interfaces.'
  desc 'The ICMP supports IP traffic by relaying information about paths, routes, and network conditions. Routers automatically send ICMP messages under a wide variety of conditions. Mask Reply ICMP messages are commonly used by attackers for network mapping and diagnosis.'
  desc 'check', 'JUNOS has no interface command to not reply to an ICMP Mask Request message destined to the router. Consequently, to ensure that the router does not send any ICMP Mask Reply message in response to an ICMP Mask Request, include a term statement in the routing engine filter to silently drop any ICMP Masks Requests sent to it as shown in the example below.

firewall {
    family inet {
       …
       …
       …
        }
        filter DESTINED_TO_RE {
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
            term DENY_MASK_REQUEST {
                from {
                    protocol icmp;
                    icmp-type mask-request;
                }
                then {
                    discard;
                }
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

If the router is not configured to silently drop all  ICMP Mask Reply messages destined to the router, this is a finding.'
  desc 'fix', 'Configure the filter protecting the routing engine to silently drop all ICMP Mask Request messages destined to the router.

[edit firewall family inet filter DESTINED_TO_RP]
set term DENY_MASK_REQUEST from protocol icmp icmp-type mask-request
insert term DENY_MASK_REQUEST before term ALLOW_ICMP'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18252r296937_chk'
  tag severity: 'medium'
  tag gid: 'V-217023'
  tag rid: 'SV-217023r604135_rule'
  tag stig_id: 'JUNI-RT-000180'
  tag gtitle: 'SRG-NET-000362-RTR-000114'
  tag fix_id: 'F-18250r296938_fix'
  tag 'documentable'
  tag legacy: ['SV-101041', 'V-90831']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
