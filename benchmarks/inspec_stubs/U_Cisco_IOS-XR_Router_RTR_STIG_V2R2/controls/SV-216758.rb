control 'SV-216758' do
  title 'The Cisco perimeter router must be configured to not redistribute static routes to an alternate gateway service provider into BGP or an IGP peering with the NIPRNet or to other autonomous systems.'
  desc 'If the static routes to the alternate gateway are being redistributed into an Exterior Gateway Protocol or Interior Gateway Protocol to a NIPRNet gateway, this could make traffic on NIPRNet flow to that particular router and not to the Internet Access Point routers. This could not only wreak havoc with traffic flows on NIPRNet, but it could overwhelm the connection from the router to the NIPRNet gateway(s) and also cause traffic destined for outside of NIPRNet to bypass the defenses of the Internet Access Points.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

Step 1: Review the IGP and BGP configurations. If there are redistribute static statements configured as shown in examples below proceed to step 2.

OSPF Example

router ospf 1
 redistribute static

EIGRP example

router eigrp 1
 address-family ipv4
  redistribute static

RIP example

router rip
 version 2
 redistribute static

BGP example

router bgp n
 address-family ipv4 unicast
  redistribute static

Step 2: Review the static routes that have been configured to determine if any contain the next hop address of the alternate gateway.

If the static routes to the alternate gateway are being redistributed into BGP or any IGP peering to a NIPRNet gateway or any other autonomous system, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

Configure the router so that static routes are not redistributed to an alternate gateway into either a BGP or any IGP peering with the NIPRNet or to any other autonomous systems. This can be done by excluding that route in the route policy as shown in the example below.

Step 1: Configure a prefix list for any static routes with the alternate gateway as the next-hop address

RP/0/0/CPU0:R3(config)#prefix-set ISP_PREFIX 
RP/0/0/CPU0:R3(config-pfx)#x.x.0.0/24 ge 8 le 32
RP/0/0/CPU0:R3(config-pfx)#end-set

Step 2: Configure a route policy

RP/0/0/CPU0:R3(config)#route-policy FILTER_ISP_ROUTES  
RP/0/0/CPU0:R3(config-rpl)#if destination in ISP_PREFIX then
RP/0/0/CPU0:R3(config-rpl-if)#drop
RP/0/0/CPU0:R3(config-rpl-if)#else
RP/0/0/CPU0:R3(config-rpl-else)#pass
RP/0/0/CPU0:R3(config-rpl-else)#endif 
RP/0/0/CPU0:R3(config-rpl)#end-pol

Step 3: Apply the route policy to the IGP and BGP redistribute static commands as shown in the OSPF example.

RP/0/0/CPU0:R3(config-ospf)#redistribute static route-policy FILTER_ISP_ROUTES'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17990r288663_chk'
  tag severity: 'low'
  tag gid: 'V-216758'
  tag rid: 'SV-216758r531087_rule'
  tag stig_id: 'CISC-RT-000300'
  tag gtitle: 'SRG-NET-000019-RTR-000010'
  tag fix_id: 'F-17988r288664_fix'
  tag 'documentable'
  tag legacy: ['SV-105861', 'V-96723']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
