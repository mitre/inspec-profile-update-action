control 'SV-251756' do
  title 'The NSX-T Tier-0 Gateway must be configured to use the BGP maximum prefixes feature to protect against route table flooding and prefix de-aggregation attacks.'
  desc "The effects of prefix de-aggregation can degrade router performance due to the size of routing tables and also result in black-holing legitimate traffic. Initiated by an attacker or a misconfigured router, prefix de-aggregation occurs when the announcement of a large prefix is fragmented into a collection of smaller prefix announcements.

In 1997, misconfigured routers in the Florida Internet Exchange network (AS7007) de-aggregated every prefix in their routing table and started advertising the first /24 block of each of these prefixes as their own. Faced with this additional burden, the internal routers became overloaded and crashed repeatedly. This caused prefixes advertised by these routers to disappear from routing tables and reappear when the routers came back online. As the routers came back after crashing, they were flooded with the routing table information by their neighbors. The flood of information would again overwhelm the routers and cause them to crash. This process of route flapping served to destabilize not only the surrounding network but also the entire internet. Routers trying to reach those addresses would choose the smaller, more specific /24 blocks first. This caused backbone networks throughout North America and Europe to crash.

Maximum prefix limits on peer connections combined with aggressive prefix-size filtering of customers' reachability advertisements will effectively mitigate the de-aggregation risk. BGP maximum prefix must be used on all eBGP routers to limit the number of prefixes that it should receive from a particular neighbor, whether customer or peering AS. Consider each neighbor and how many routes they should be advertising and set a threshold slightly higher than the number expected."
  desc 'check', 'If the Tier-0 Gateway is not using BGP, this is Not Applicable.

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways.

For every Tier-0 Gateway with BGP enabled, expand the Tier-0 Gateway.

Expand BGP, click on the number next to BGP Neighbors, and then view the Router Filters for each neighbor.

If Maximum Routes is not configured or a route filter does not exist for each BGP neighbor, this is a finding.'
  desc 'fix', 'To set maximum prefixes for BGP neighbors do the following:

From the NSX-T Manager web interface, go to Networking >> Tier-0 Gateways and expand the target Tier-0 gateway.

Expand BGP. Next to BGP Neighbors, click on the number present to open the dialog, and then select "Edit" on the target BGP Neighbor.

Click "Router Filter", add or edit an existing router filter, enter a number for Maximum Routes, and then click "Add".

Click "Apply", then click "Save" to finish the configuration.'
  impact 0.5
  ref 'DPMS Target VMware NSX-T Tier-0 Gateway RTR'
  tag check_id: 'C-55193r810150_chk'
  tag severity: 'medium'
  tag gid: 'V-251756'
  tag rid: 'SV-251756r810152_rule'
  tag stig_id: 'T0RT-3X-000067'
  tag gtitle: 'SRG-NET-000362-RTR-000117'
  tag fix_id: 'F-55147r810151_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
