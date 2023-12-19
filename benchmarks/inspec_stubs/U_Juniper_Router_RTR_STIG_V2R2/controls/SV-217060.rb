control 'SV-217060' do
  title 'The Juniper BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.'
  desc "The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) de-aggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal routers became overloaded and crashed repeatedly. This caused prefixes advertised by these routers to disappear from routing tables and reappear when the routers came back online. As the routers came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the routers and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire Internet. Routers trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the de-aggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected."
  desc 'check', 'Review the router configuration to verify that the number of received prefixes from each eBGP neighbor is controlled.

protocols {
    bgp {
        group GROUP_AS4 {
            type external;
             family inet {
                unicast {
                    prefix-limit {
                        maximum 10;
                        teardown;
                    }
                }
            }            peer-as 4;
            neighbor x.x.x.x;
        }

If the router is not configured to control the number of prefixes received from each peer to protect against route table flooding and prefix de-aggregation attacks, this is a finding.'
  desc 'fix', 'Configure the router to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks as shown in the example below.

[edit protocols bgp group GROUP_AS4]
set family inet unicast prefix-limit maximum nnnnn teardown'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18289r297048_chk'
  tag severity: 'medium'
  tag gid: 'V-217060'
  tag rid: 'SV-217060r639663_rule'
  tag stig_id: 'JUNI-RT-000540'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag fix_id: 'F-18287r297049_fix'
  tag 'documentable'
  tag legacy: ['V-90903', 'SV-101113']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
