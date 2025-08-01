control 'SV-256045' do
  title 'The Arista multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the Arista DR to verify it is filtering IGMP or MLD report messages, allowing hosts to join only groups that have been approved.

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. This requirement is not applicable to Any Source Multicast (ASM) because the filtering is being performed by the Rendezvous Point router.

Step 1: Verify the ACL filters the unauthorized IGMP groups. The ACL below is blocking the IGMP group sourced 232.0.0.0/8. Execute the command "sh ip access-list".

ip access-list FILTER_IGMP
  10 deny igmp 232.0.0.0/8 any
  20 permit ip any any

Step 2: Verify the ACL is configured on internal host-facing interfaces (IGMP process) to filter IGMP.

router igmp
  ip igmp access-group FILTER_IGMP

or 

interface ethernet 3
 ip access-group FILTER_IGMP

If the Arista DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the Arista DR to filter the IGMP and MLD report messages to allow hosts to join only multicast groups that have been approved.

Step 1: Configure the ACL to filter the unauthorized IGMP groups.

LEAF-1A(config-if-Et3)#ip access-list FILTER_IGMP
LEAF-1A(config-acl-FILTER_IGMP)#  10 deny igmp 232.0.0.0/8 any
LEAF-1A(config-acl-FILTER_IGMP)#  20 permit ip any any

Step 2: Configure the IGMP filter in IGMP process.

LEAF-1A(config-acl-FILTER_IGMP)#router igmp
LEAF-1A(config-router-igmp)#  ip igmp access-group FILTER_IGMP

or 

Configure the IGMP filter on internal host-facing interfaces (IGMP process) to filter IGMP.

LEAF-1A(config-router-igmp)#interface ethernet 3
LEAF-1A(config-if-Et3)# ip access-group FILTER_IGMP in'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59721r882475_chk'
  tag severity: 'low'
  tag gid: 'V-256045'
  tag rid: 'SV-256045r882477_rule'
  tag stig_id: 'ARST-RT-000660'
  tag gtitle: 'SRG-NET-000364-RTR-000114'
  tag fix_id: 'F-59664r882476_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
