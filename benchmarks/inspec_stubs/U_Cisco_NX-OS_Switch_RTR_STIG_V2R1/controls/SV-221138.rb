control 'SV-221138' do
  title 'The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD Membership Report messages, allowing hosts to join only those groups that have been approved.

Step 1: Verify that all host facing interfaces are configured to filter IGMP Membership Report messages (IGMP joins) as shown in the example below:

interface Ethernet2/4
 no switchport
 ip address 10.2.22.3/24 ip pim sparse-mode
 ip igmp version 3
 ip igmp report-policy ALLOWED_GROUPS

Step 2: Verify that the report policy denies unauthorized groups or permits only authorized groups. 

route-map ALLOWED_GROUPS permit 10
 match ip multicast group 233.1.1.0/24 
route-map ALLOWED_GROUPS permit 20
 match ip multicast group 233.1.1.0/32 
route-map ALLOWED_GROUPS permit 30
 match ip multicast group 233.1.1.1/32 
route-map ALLOWED_GROUPS deny 40
 match ip multicast group 224.0.0.0/4

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. This requirement is not applicable to Any Source Multicast (ASM) since the filtering is being performed by the Rendezvous Point.

If the DR is not filtering IGMP or MLD Membership Report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP or MLD Membership Report messages to allow hosts to join only those multicast groups that have been approved.

Step 1: Configure the report policy to filter IGMP Membership Report messages as shown in the example below:

SW1(config)# route-map ALLOWED_GROUPS permit
SW1(config-route-map)# match ip multicast group 233.1.1.0/24
SW1(config-route-map)# route-map ALLOWED_GROUPS permit 20
SW1(config-route-map)# match ip multicast group 233.1.1.0/32
SW1(config-route-map)# route-map ALLOWED_GROUPS permit 30
SW1(config-route-map)# match ip multicast group 233.1.1.1/32
SW1(config-route-map)# route-map ALLOWED_GROUPS deny 40
SW1(config-route-map)# match ip multicast group 224.0.0.0/4
SW1(config-route-map)# exit

Step 2: Apply the report policy to all applicable interfaces.

SW1(config)# int e2/4
SW1(config-if)# ip igmp report-policy ALLOWED_GROUPS 
SW1(config-if)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22853r409903_chk'
  tag severity: 'low'
  tag gid: 'V-221138'
  tag rid: 'SV-221138r622190_rule'
  tag stig_id: 'CISC-RT-000860'
  tag gtitle: 'SRG-NET-000364-RTR-000114'
  tag fix_id: 'F-22842r409904_fix'
  tag 'documentable'
  tag legacy: ['SV-111169', 'V-102213']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
