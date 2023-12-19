control 'SV-220464' do
  title 'The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.'
  desc "Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast group's hosts are allowed to join via IGMP or MLD."
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD Membership Report messages, allowing hosts to join only groups that have been approved. 

Step 1: Verify that all host-facing Layer 3 and VLAN interfaces are configured to filter IGMP Membership Report messages (IGMP joins) as shown in the example below: 

interface Vlan3 
 ip address 10.3.3.3 255.255.255.0 
 ip pim sparse-mode 
 ip igmp access-group IGMP_JOIN_FILTER 
 ip igmp version 3 

Step 2: Verify that the ACL denies unauthorized groups or permits only authorized groups. The example below denies all groups from 239.8.0.0/16 range. 

ip access-list standard IGMP_JOIN_FILTER 
 deny 239.8.0.0 0.0.255.255 
 permit any 

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. This requirement is not applicable to Any Source Multicast (ASM) since the filtering is being performed by the Rendezvous Point switch. 

If the DR is not filtering IGMP or MLD Membership Report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP or MLD Membership Report messages to allow hosts to join only multicast groups that have been approved. 

Step 1: Configure the ACL to filter IGMP Membership Report messages as shown in the example below: 

SW2(config)#ip access-list standard IGMP_JOIN_FILTER 
SW2(config-std-nacl)#deny 239.8.0.0 0.0.255.255 
SW2(config-std-nacl)#permit any 
SW2(config-std-nacl)#exit 

Step 2: Apply the filter to all host-facing Layer 3 and VLAN interfaces. 

SW2(config)#int vlan3 
SW2(config-if)#ip igmp access-group IGMP_JOIN_FILTER'
  impact 0.3
  ref 'DPMS Target Cisco IOS Switch RTR'
  tag check_id: 'C-22179r508467_chk'
  tag severity: 'low'
  tag gid: 'V-220464'
  tag rid: 'SV-220464r622190_rule'
  tag stig_id: 'CISC-RT-000860'
  tag gtitle: 'SRG-NET-000364-RTR-000114'
  tag fix_id: 'F-22168r508468_fix'
  tag 'documentable'
  tag legacy: ['SV-110783', 'V-101679']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
