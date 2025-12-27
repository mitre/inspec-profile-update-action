control 'SV-80593' do
  title 'If Border Gateway Protocol (BGP) is enabled on the HP FlexFabric Switch, the HP FlexFabric Switch must not be a BGP peer with a HP FlexFabric Switch from an Autonomous System belonging to any Alternate Gateway (AG).'
  desc 'The perimeter router will not use a routing protocol to advertise NIPRNet addresses to Alternate Gateways. Most ISPs use Border Gateway Protocol (BGP) to share route information with other autonomous systems, that is, any network under a different administrative control and policy than a local site. If BGP is configured on the perimeter router, no BGP neighbors will be defined to peer routers from an AS belonging to any Alternate Gateway. The only allowable method is a static route to reach the Alternate Gateway.'
  desc 'check', 'Review the configuration of the HP FlexFabric Switch connecting to the AG.

Verify there are no BGP neighbors configured to the remote AS that belongs to the AG service provider. There should be no BGP peers displayed.

If there are BGP neighbors configured that belong to the AG service provider, this is a finding.

[HP] display bgp peer ipv4

 BGP local FlexFabric Switch ID: 2.2.2.0
 Local AS number: 1472
 Total number of peers: 1                 Peers in established state: 0

  * - Dynamically created peer
  Peer                    AS  MsgRcvd  MsgSent OutQ PrefRcv Up/Down  State'
  desc 'fix', 'Configure a static route on the perimeter HP FlexFabric Switch to reach the AS of a HP FlexFabric Switch connecting to an Alternate Gateway.

[HP] ip route-static 11.11.11.0 16 12.12.12.2'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66103'
  tag rid: 'SV-80593r1_rule'
  tag stig_id: 'HFFS-RT-000004'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-72179r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
