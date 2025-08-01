control 'SV-217073' do
  title 'The Juniper PE router providing Virtual Private LAN Services (VPLS) must be configured to have traffic storm control thresholds on CE-facing interfaces.'
  desc 'A traffic storm occurs when packets flood a VPLS bridge, creating excessive traffic and degrading network performance. Traffic storm control prevents VPLS bridge disruption by suppressing traffic when the number of packets reaches configured threshold levels. Traffic storm control monitors incoming traffic levels on a port and drops traffic when the number of packets reaches the configured threshold level during any one-second interval.'
  desc 'check', 'Review the router configuration to verify that storm control is enabled on CE-facing interfaces deploying VPLS.

Verify that a flood filter has been configured for each VPLS routing instances as shown in the example below.

routing-instances {
    VPLS_CUST2 {
        instance-type vpls;
        interface ge-0/1/0.0;  
        route-distinguisher 22:22;
        vrf-target target:22:22;
        forwarding-options {
            family vpls {
                 flood {
                    input VPLS_FLOOD_FILTER;
                 }
            }
        }
        protocols {
            vpls {
                site-range 9;
                no-tunnel-services;
                site R8 {
                    site-identifier 8;
                    interface ge-0/1/0.0;
                }
                vpls-id 102;
                neighbor 8.8.8.8;
            }
        }
    }
}

Review the filter configured for the VPLS routing instances to verify it defines traffic types associated with storm control (i.e. broadcast, multicast, and unknown unicast storms).

firewall {
    …
    …
    …
    family vpls {
        filter VPLS_FLOOD_FILTER {
            term BROADCAST_TRAFFIC {
                from {
                    traffic-type broadcast;
                }
                then {
                    policer STORM_POLICER;
                    accept;
                }
            }
            term MULTICAST_TRAFFIC {
                from {
                    traffic-type multicast;
                }
                then {
                    policer STORM_POLICER;
                    accept;
                }
            }
            term UNKNOWN_UNICAST_TRAFFIC {
                from {
                    traffic-type unknown-unicast;
                }
                then {
                    policer STORM_POLICER;
                    accept;
                }
            }
        }
    }

Verify that the policer rates limits storm traffic.

firewall {
    …
    …
    …
    policer STORM_POLICER {
        if-exceeding {
            bandwidth-limit 10m;
            burst-size-limit 5m;
        }
        then discard;
    }

If storm control is not enabled, this is a finding.'
  desc 'fix', 'Configure storm control for each VPLS bridge domain. Base the rate limiting on expected traffic rates plus some additional capacity. 

Configure a policer to rate limit traffic to provide storm control for all VPLS implementations as shown in the example.

[edit firewall]
set policer STORM_POLICER if-exceeding bandwidth-limit 10m burst-size-limit 5m
set policer STORM_POLICER then discard

Configure the filter to specify traffic types to rate limit broadcast, multicast, and unknown unicast storms as shown in the example.

[edit firewall family vpls filter VPLS_FLOOD_FILTER]
set term BROADCAST_TRAFFIC from traffic-type broadcast
set term BROADCAST_TRAFFIC then policer STORM_POLICER accept
set term MULTICAST_TRAFFIC from traffic-type multicast
set term MULTICAST_TRAFFIC then policer STORM_POLICER accept
set term UNKNOWN_UNICAST_TRAFFIC from traffic-type unknown-unicast 
set term UNKNOWN_UNICAST_TRAFFIC then policer STORM_POLICER accept 

Apply the storm control filter to all VPLS routing instances as shown in the example.

[edit routing-instances VPLS_CUST2]
set forwarding-options family vpls flood input VPLS_FLOOD_FILTER'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18302r297087_chk'
  tag severity: 'medium'
  tag gid: 'V-217073'
  tag rid: 'SV-217073r639663_rule'
  tag stig_id: 'JUNI-RT-000680'
  tag gtitle: 'SRG-NET-000193-RTR-000002'
  tag fix_id: 'F-18300r297088_fix'
  tag 'documentable'
  tag legacy: ['V-90927', 'SV-101137']
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
