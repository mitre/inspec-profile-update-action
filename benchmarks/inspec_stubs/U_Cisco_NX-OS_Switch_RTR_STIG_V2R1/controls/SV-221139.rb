control 'SV-221139' do
  title 'The Cisco multicast Designated switch (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved.

Step 1: Verify that all host-facing interfaces are configured to filter IGMP Membership Report messages (IGMP joins) as shown in the example below:

interface Ethernet2/4
 no switchport
 ip address 10.2.22.3/24 
 ip pim sparse-mode
 ip igmp version 3
 ip igmp report-policy ALLOWED_SOURCES

Step 2: Verify that the report policy permits only sources that have been approved by the organization.

route-map ALLOWED_SOURCES permit 10
 match ip multicast source x.1.2.6/32 
route-map ALLOWED_SOURCES permit 20
 match ip multicast source x.1.2.7/32 
route-map ALLOWED_SOURCES deny 30
 match ip multicast source 0.0.0.0/0

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation.

If the DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Step 1: Configure the report policy to filter IGMP Membership Report messages as shown in the example below:

SW1(config-route-map)# route-map ALLOWED_SOURCES permit 10
SW1(config-route-map)# match ip multicast source x.1.2.6/32
SW1(config-route-map)# route-map ALLOWED_SOURCES permit 20
SW1(config-route-map)# match ip multicast source x.1.2.7/32
SW1(config-route-map)# route-map ALLOWED_SOURCES deny 30
SW1(config-route-map)# match ip multicast source 0.0.0.0/0
SW1(config-route-map)# exit

Step 2: Apply the report policy to all applicable interfaces.

SW1(config)# int e2/4
SW1(config-if)# ip igmp report-policy ALLOWED_SOURCES 
SW1(config-if)# end'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22854r409906_chk'
  tag severity: 'medium'
  tag gid: 'V-221139'
  tag rid: 'SV-221139r622190_rule'
  tag stig_id: 'CISC-RT-000870'
  tag gtitle: 'SRG-NET-000364-RTR-000115'
  tag fix_id: 'F-22843r409907_fix'
  tag 'documentable'
  tag legacy: ['SV-111171', 'V-102215']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
