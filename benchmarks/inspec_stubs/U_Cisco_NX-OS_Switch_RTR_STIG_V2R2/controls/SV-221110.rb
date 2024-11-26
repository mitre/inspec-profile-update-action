control 'SV-221110' do
  title 'The Cisco BGP switch must be configured to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.'
  desc "The effects of prefix de-aggregation can degrade switch performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured switch, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

In 1997, misconfigured switches in the Florida Internet Exchange network (AS7007) de-aggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal switches became overloaded and crashed repeatedly. This caused prefixes advertised by these switches to disappear from routing tables and reappear when the switches came back online. As the switches came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the switches and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire Internet. Switches trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the de-aggregation risk. BGP maximum prefix must be used on all eBGP switches to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected."
  desc 'check', 'Review the switch configuration to verify that the number of received prefixes from each eBGP neighbor is controlled.

router bgp xx
 router-id 10.1.1.1
 neighbor x.1.12.2 remote-as xx
 password 3 7b07d1b3023056a9
 address-family ipv4 unicast
 maximum-prefix nnnnnnn
 neighbor x.2.44.4 remote-as xx
 password 3 f07a10cb41db8bb6f8f0a340049a9b02
 address-family ipv4 unicast
 maximum-prefix nnnnnnn

If the switch is not configured to control the number of prefixes received from each peer to protect against route table flooding and prefix de-aggregation attacks, this is a finding.'
  desc 'fix', 'Configure the switch to use the maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks as shown in the example below:

SW1(config)# router bgp xx
SW1(config-router)# neighbor x.1.12.2
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# maximum-prefix nnnnnnn
SW1(config-router-neighbor-af)# exit
SW1(config-router-neighbor)# exit
SW1(config-router)# neighbor x.2.44.4
SW1(config-router-neighbor)# address-family ipv4 unicast
SW1(config-router-neighbor-af)# maximum-prefix nnnnnnn 
SW1(config-router-neighbor-af)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22825r409819_chk'
  tag severity: 'medium'
  tag gid: 'V-221110'
  tag rid: 'SV-221110r856640_rule'
  tag stig_id: 'CISC-RT-000560'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag fix_id: 'F-22814r409820_fix'
  tag 'documentable'
  tag legacy: ['SV-111039', 'V-101935']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
