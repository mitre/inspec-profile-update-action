control 'SV-216625' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'The Cisco router does not have a mechanism to limit the multicast forwarding cache. However, the risk associated with this requirement can be fully mitigated by configuring the router to:

1. Filter PIM register messages.
2. Rate limiting the number of PIM register messages.
3. Accept MSDP packets only from known MSDP peers.

Step 1:  Verify that the RP router is configured to filter PIM register messages for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

ip pim rp-address 10.1.12.3
ip pim accept-register list PIM_REGISTER_FILTER
…
…
…
ip access-list extended PIM_REGISTER_FILTER
 deny   ip any 239.5.0.0 0.0.255.255
 permit ip host 10.1.2.6 any
 permit ip host 10.1.2.7 any
 deny   ip any any

Step 2: Verify that the router is configured to rate limiting the number of PIM register messages as shown in the example below.

ip pim rp-address 10.2.2.2
ip pim register-rate-limit nn

Step 3: Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers as shown in the example below.

Step 3a: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example.

interface GigabitEthernet1/1
 ip address x.1.28.8 255.255.255.0
 ip access-group EXTERNAL_ACL_INBOUND in
 ip pim sparse-mode

Step 3b: Verify that the ACL restricts MSDP peering to only known sources.

ip access-list extended EXTERNAL_ACL_INBOUND
 permit tcp any any established
 permit tcp host x.1.28.2 host x.1.28.8 eq 639
 deny   tcp any host x.1.28.8 eq 639 log
 permit tcp host x.1.28.2 host 10.1.28.8 eq bgp
 permit tcp host x.1.28.2 eq bgp host x.1.28.8
 permit pim host x.1.28.2 pim host x.1.28.8
 …
 …
 …
 deny ip any any log

Note: MSDP connections is via TCP port 639

If the RP router is not configured to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers, this is a finding.'
  desc 'fix', 'The risk associated with this requirement can be fully mitigated by configuring the router to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers.

Step 1: Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

R2(config)#ip access-list extended PIM_REGISTER_FILTER
R2(config-ext-nacl)#deny ip any 239.5.0.0 0.0.255.255
R2(config-ext-nacl)#permit ip host 10.1.2.6 any
R2(config-ext-nacl)#permit ip host 10.1.2.7 any
R2(config-ext-nacl)#deny ip any any
R2(config-ext-nacl)#exit
R2(config)#ip pim accept-register list PIM_REGISTER_FILTER
R2(config)#end 

Step 2: Configure the RP to rate limit the number of multicast register messages.

R2(config)#ip pim register-rate-limit nn

Step 3: Configure the receive path or interface ACLs to only accepts MSDP packets from known MSDP peers.

R8(config)#ip access-list extended EXTERNAL_ACL_INBOUND
R8(config-ext-nacl)#permit tcp any any established
R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639
R8(config-ext-nacl)#deny tcp any host x.1.28.8 eq 639
R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp
R8(config-ext-nacl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8
R8(config-ext-nacl)#permit pim host x.1.28.2 host x.1.28.8
…
…
…
R8(config-ext-nacl)#deny ip any any'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17860r508005_chk'
  tag severity: 'low'
  tag gid: 'V-216625'
  tag rid: 'SV-216625r531085_rule'
  tag stig_id: 'CISC-RT-000820'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-17856r508006_fix'
  tag 'documentable'
  tag legacy: ['V-96649', 'SV-105787']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
