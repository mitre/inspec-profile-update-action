control 'SV-216815' do
  title 'The Cisco multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved.

Step 1: Verify that all host facing interfaces are configured to filter IGMP Membership Report messages (IGMP joins) as shown in the example below.

router igmp
 interface GigabitEthernet0/0/1/0
  access-group IGMP_JOIN_FILTER
 !
 interface GigabitEthernet0/0/1/1
  access-group IGMP_JOIN_FILTER
 !

Step 2: Verify that the ACL denies unauthorized sources or allows only authorized sources. The example below denies all groups from 232.8.0.0/16 range and permits sources only from the x.0.0.0/8 network.

ipv4 access-list IGMP_JOIN_FILTER
 10 deny ipv4 any 232.8.0.0 0.0.255.255
 20 permit ipv4 x.0.0.0 0.255.255.255 any
 30 deny ipv4 any any
!

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation.

If the DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups from sources that have been approved as shown in the example.

Step 1: Configure the access list to filter multicast joins as shown in the example below.

RP/0/0/CPU0:R2(config)#ipv4 access-list IGMP_JOIN_FILTER
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any 232.8.0.0 0.0.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ip x.0.0.0 0.255.255.255 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any any

Step 2: Apply the filter to all host facing interfaces.

RP/0/0/CPU0:R5(config)#router igmp 
RP/0/0/CPU0:R5(config-igmp)#interface g0/0/1/0 
RP/0/0/CPU0:R5(config-igmp-default-if)#access-group IGMP_JOIN_FILTER
RP/0/0/CPU0:R5(config-igmp-default-if)#exit
RP/0/0/CPU0:R5(config-igmp)#interface g0/0/1/1
RP/0/0/CPU0:R5(config-igmp-default-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18047r507371_chk'
  tag severity: 'medium'
  tag gid: 'V-216815'
  tag rid: 'SV-216815r531087_rule'
  tag stig_id: 'CISC-RT-000870'
  tag gtitle: 'SRG-NET-000364-RTR-000115'
  tag fix_id: 'F-18045r507372_fix'
  tag 'documentable'
  tag legacy: ['SV-105975', 'V-96837']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
