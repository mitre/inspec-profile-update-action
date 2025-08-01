control 'SV-220465' do
  title 'The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved. 

Step 1: Verify that all host-facing Layer 3 and VLAN interfaces are configured to filter IGMP Membership Report messages (IGMP joins) as shown in the example below: 

interface Vlan3 
 ip address 10.3.3.3 255.255.255.0 
 ip pim sparse-mode 
 ip igmp access-group IGMP_JOIN_FILTER 
 ip igmp version 3 

Step 2: Verify that the ACL denies unauthorized sources or allows only authorized sources. The example below denies all groups from the 232.8.0.0/16 range and permits sources only from the x.0.0.0/8 network. 

ip access-list extended IGMP_JOIN_FILTER 
 deny ip any 232.8.0.0 0.0.255.255 
 permit ip x.0.0.0 0.255.255.255 any 
 deny ip any any 

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. 

If the DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only multicast groups from sources that have been approved as shown in the example below: 

SW2(config)#ip access-list extended IGMP_JOIN_FILTER 
SW2(config-ext-nacl)#deny ip any 232.8.0.0 0.0.255.255 
SW2(config-ext-nacl)#permit ip x.0.0.0 0.255.255.255 any 
SW2(config-ext-nacl)#deny ip any any 
SW2(config-ext-nacl)#exit 

Step 2: Apply the filter to all host-facing Layer 3 and VLAN interfaces. 

SW2(config)#int vlan3 
SW2(config-if)#ip igmp access-group IGMP_JOIN_FILTER'
  impact 0.5
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22180r508469_chk'
  tag severity: 'medium'
  tag gid: 'V-220465'
  tag rid: 'SV-220465r864161_rule'
  tag stig_id: 'CISC-RT-000870'
  tag gtitle: 'SRG-NET-000364-RTR-000115'
  tag fix_id: 'F-22169r508470_fix'
  tag 'documentable'
  tag legacy: ['SV-111269', 'V-102313']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
