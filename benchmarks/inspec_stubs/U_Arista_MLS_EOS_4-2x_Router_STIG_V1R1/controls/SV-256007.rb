control 'SV-256007' do
  title 'The multicast Rendezvous Point (RP) Arista router must be configured to filter Protocol Independent Multicast (PIM) Register and Join messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.

'
  desc 'check', 'Verify that the RP router is configured to filter PIM register and join messages. 

Step 1: To verify the ACL is configured to filter the multicast groups, execute the command "show ip access-lists".

ip access-list standard ALLOWED_MULTICAST_GROUP
   10 permit 224.0.0.0/8
   20 deny any

Step 2: To verify the ACL is applied to the PIM process, execute the command "show run section router pim".

router pim sparse-mode
   ipv4
      rp address 100.2.1.6 access-list ALLOWED_MULTICAST_GROUP

If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the RP router to filter PIM register and join messages received from a multicast DR for any undesirable multicast groups or sources.

Step 1: Configure an ACL to filter the multicast groups.

LEAF-1A(config)#ip access-list standard ALLOWED_MULTICAST_GROUP
LEAF-1A(config-std-acl-ALLOWED_MULTICAST_GROUP)#10 permit 224.0.0.0/8
LEAF-1A(config-std-acl-ALLOWED_MULTICAST_GROUP)#20 deny any

Step 2: Apply the ACL in the PIM process globally.

LEAF-1A(config)#router pim sparse-mode
LEAF-1A(config-router-pim-sparse)#ipv4
LEAF-1A(config-router-pim-sparse-ipv4)#rp address 100.2.1.6 access-list ALLOWED_MULTICAST_GROUP'
  impact 0.3
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59683r882361_chk'
  tag severity: 'low'
  tag gid: 'V-256007'
  tag rid: 'SV-256007r882363_rule'
  tag stig_id: 'ARST-RT-000210'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-59626r882362_fix'
  tag satisfies: ['SRG-NET-000019-RTR-000013', 'SRG-NET-000019-RTR-000014']
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
