control 'SV-254005' do
  title 'The Juniper PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the router configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS.

Verify that a stateless firewall filter has been applied to each VPLS routing instances.

[edit]
routing-instances {
    <name> {
        forwarding-options {
            family vpls {
                flood {
                    input <filter name>;
                }
            }
        }
    }
}

Verify the filter defines traffic types associated with storm control (i.e., broadcast, multicast, and unknown unicast storms).

firewall {
    family vpls {
        filter <filter name> {
            term <term name> {
                from {
                    traffic-type broadcast;
                }
                then {
                    policer <policer name>;
                    accept;
                }
            }
            term <term name> {
                from {
                    traffic-type multicast;
                }
                then {
                    policer <policer name>;
                    accept;
                }
            }
            term <term name> {
                from {
                    traffic-type unknown-unicast;
                }
                then {
                    policer <policer name>;
                    accept;
                }
            }
        }
    }
}

Verify that the policer rate limits in accordance with local requirements.

firewall {
    policer <policer name> {
        if-exceeding {
            bandwidth-limit <value>;
            burst-size-limit <value>;
        }
        then discard;
    }
}

Note: Only EX9200-series devices currently support VPLS.

If storm control is not enabled for broadcast traffic, this is a finding.'
  desc 'fix', 'Configure storm control for each CE-facing interface deploying VPLS bridge domains. Base the suppression threshold on expected traffic rates plus some additional capacity. 

Configure a policer to rate limit traffic providing storm control in accordance with organizational requirements.

set firewall policer <policer name> if-exceeding bandwidth-limit <value> burst-size-limit <value>
set firewall policer <policer name> then discard

Configure the filter providing storm control to specify traffic types and rate limit broadcast, multicast, and unknown unicast storms.

set firewall family vpls filter <filter name> term <term name> from traffic-type broadcast
set firewall family vpls filter <filter name> term <term name> then policer <policer name> accept
set firewall family vpls filter <filter name> term <term name> from traffic-type multicast
set firewall family vpls filter <filter name> term <term name> then policer <policer name> accept
set firewall family vpls filter <filter name> term <term name> from traffic-type unknown-unicast
set firewall family vpls filter <filter name> term <term name> then policer <policer name> accept

Apply the storm control filter to all CE-facing instances deploying VPLS bridge domains.

set routing-instances <instance name> forwarding-options family vpls flood input <filter name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57457r844046_chk'
  tag severity: 'medium'
  tag gid: 'V-254005'
  tag rid: 'SV-254005r844048_rule'
  tag stig_id: 'JUEX-RT-000330'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-57408r844047_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
