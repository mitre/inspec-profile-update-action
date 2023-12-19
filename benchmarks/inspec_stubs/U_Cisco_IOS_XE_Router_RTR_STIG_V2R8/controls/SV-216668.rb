control 'SV-216668' do
  title 'The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an Interior Gateway Protocol (IGP) peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Review the IGP and BGP configurations. If there are redistribute static statements configured as shown in examples below, proceed to step 2.

OSPF Example:

router ospf 1
 log-adjacency-changes
 redistribute static subnets
 network 0.0.0.0 255.255.255.255 area 0

EIGRP example:

router eigrp 1
 network 10.1.15.0 0.0.0.255
 redistribute static

RIP example:

router rip
 version 2
 redistribute static
 network 10.0.0.0

BGP example:

router bgp nn
 no synchronization
 bgp log-neighbor-changes
 redistribute static
 neighbor x.11.1.7 remote-as nn
 neighbor x.11.1.7 password xxxxxxx
 no auto-summary

Step 2: Review the static routes that have been configured to determine if any contain the next hop address of the alternate gateway.

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering to a NIPRNet gateway or any other autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router so that static routes are not redistributed to an alternate gateway into either a BGP or any IGP peering with the NIPRNet or to any other autonomous systems. This can be done by excluding that route in the route-map as shown in the example below:

Step 1: Configure a prefix list for any static routes with the alternate gateway as the next-hop address.

R5(config)#ip prefix-list ISP_PREFIX permit x.x.x.0/24

Step 2: Configure a route map that will deny the state routes to the ISP.

R5(config)#route-map FILTER_ISP_STATIC deny 10
R5(config-route-map)#match ip address prefix-list ISP_PREFIX
R5(config-route-map)#exit
R5(config)#route-map FILTER_ISP_STATIC permit 20
R5(config-route-map)#exit

Step 3: Apply the route-map to the IGP and BGP redistribute static commands as shown in the EIGRP example.

R5(config)#router eigrp 1
R5(config-router)#redistribute static route-map FILTER_ISP_STATIC'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17901r287961_chk'
  tag severity: 'low'
  tag gid: 'V-216668'
  tag rid: 'SV-216668r531086_rule'
  tag stig_id: 'CISC-RT-000300'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-17899r287962_fix'
  tag 'documentable'
  tag legacy: ['SV-106047', 'V-96909']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
