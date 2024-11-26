control 'SV-256035' do
  title 'The Arista BGP router must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.'
  desc "The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) de-aggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal routers became overloaded and crashed repeatedly. This caused prefixes advertised by these routers to disappear from routing tables and reappear when the routers came back online. As the routers came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the routers and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire internet. Routers trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the de-aggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected."
  desc 'check', 'Review the Arista router configuration to verify the number of received prefixes from each eBGP neighbor is controlled.

To verify in the BGP configuration that number of received prefixes from each eBGP neighbor is controlled, execute the command "sh rnu section router bgp".

router bgp NNN
 neighbor x.1.12.1 remote-as YYY
 neighbor x.1.12.1 maximum-routes 12000
 neighbor x.1.12.1 maximum-accepted-routes 10000

If the Arista router is not configured to control the number of prefixes received from each peer to protect against route table flooding and prefix deaggregation attacks, this is a finding.'
  desc 'fix', 'Configure all eBGP Arista routers to use the maximum prefixes feature to protect against route table flooding and prefix deaggregation attacks.

Configure each BGP neighbor to control the number of prefixes.

router bgp NNN
 neighbor x.1.12.1 remote-as YYY
 neighbor x.1.12.1 maximum-routes 12000
 neighbor x.1.12.1 maximum-accepted-routes 10000'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59711r882445_chk'
  tag severity: 'medium'
  tag gid: 'V-256035'
  tag rid: 'SV-256035r882447_rule'
  tag stig_id: 'ARST-RT-000560'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag fix_id: 'F-59654r882446_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
