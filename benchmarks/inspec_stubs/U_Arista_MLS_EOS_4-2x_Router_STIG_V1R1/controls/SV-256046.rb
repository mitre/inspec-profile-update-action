control 'SV-256046' do
  title 'The Arista multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the Arista DR to verify it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved.

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation.

Step 1: To verify the ACL filters the unauthorized IGMP joins, execute the command "sh ip access-list".

ip access-list standard ALLOWED_SOURCES
  10 permit 232.0.0.0/8
  20 deny any log
  
Step 2: Verify the ACL is configured on internal host-facing interfaces (pim process) to filter IGMP joins.

router pim sparse-mode
  ipv4 
    ssm range ALLOWED_SOURCES

If the Arista DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the Arista DR to filter the IGMP and MLD report messages to allow hosts to join only multicast groups from sources that have been approved.

Step 1: Configure the ACL to filter the unauthorized IGMP groups.

LEAF-1A(config-if-Et3)#ip access-list standard ALLOWED_SOURCES
LEAF-1A(config-std-acl-ALLOWED_SOURCES)#  10 permit 232.0.0.0/8
LEAF-1A(config-std-acl-ALLOWED_SOURCES)#  20 deny any log

Step 2: Configure the IGMP filter in IGMP process.

LEAF-1A(config)#router pim sparse-mode
LEAF-1A(config-router-pim-sparse)#  ipv4 
LEAF-1A(config-router-pim-sparse-ipv4)#    ssm range ALLOWED_SOURCES'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59722r882478_chk'
  tag severity: 'medium'
  tag gid: 'V-256046'
  tag rid: 'SV-256046r882480_rule'
  tag stig_id: 'ARST-RT-000670'
  tag gtitle: 'SRG-NET-000364-RTR-000115'
  tag fix_id: 'F-59665r882479_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
