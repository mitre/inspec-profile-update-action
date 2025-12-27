control 'SV-221056' do
  title 'The Cisco multicast Rendezvous Point (RP) switch must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP switches to peer with MSDP switches. As a first step of defense against a denial-of-service (DoS) attack, all RP switches must limit the multicast forwarding cache to ensure that switch resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'The Cisco switch does not have a mechanism to limit the multicast forwarding cache. However, the risk associated with this requirement can be fully mitigated by configuring the switch to: 

1. Filter PIM register messages. 
2. Rate limiting the number of PIM register messages. 
3. Accept MSDP packets only from known MSDP peers. 

Step 1: Verify that the RP is configured to filter PIM register messages for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

ip pim rp-address 10.1.12.3 
ip pim accept-register list PIM_REGISTER_FILTER 
… 
… 
… 
ip access-list extended PIM_REGISTER_FILTER 
deny ip any 239.5.0.0 0.0.255.255 
permit ip host x.1.2.6 any 
permit ip host x.1.2.7 any 
deny ip any any 

Step 2: Verify that the RP is configured to rate limiting the number of PIM register messages as shown in the example below: 

ip pim rp-address 10.2.2.2 
ip pim register-rate-limit nn 

Step 3: Review the switch configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers as shown in the example below: 

Step 3a: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example. 

interface GigabitEthernet1/1 
ip address x.1.28.8 255.255.255.0 
ip access-group EXTERNAL_ACL_INBOUND in 
ip pim sparse-mode 

Step 3b: Verify that the ACL restricts MSDP peering to only known sources. 

ip access-list extended EXTERNAL_ACL_INBOUND 
permit tcp any any established 
permit tcp host x.1.28.2 host x.1.28.8 eq 639 
deny tcp any host x.1.28.8 eq 639 log 
permit tcp host x.1.28.2 host 10.1.28.8 eq bgp 
permit tcp host x.1.28.2 eq bgp host x.1.28.8 
permit pim host x.1.28.2 pim host x.1.28.8 
… 
… 
… 
deny ip any any log 

Note: MSDP connections is via TCP port 639.

If the RP switch is not configured to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers, this is a finding.'
  desc 'fix', 'The risk associated with this requirement can be fully mitigated by configuring the switch to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers. 

Step 1: Configure the switch to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

SW1(config)#ip access-list extended PIM_REGISTER_FILTER 
SW1(config-ext-nacl)#deny ip any 239.5.0.0 0.0.255.255 
SW1(config-ext-nacl)#permit ip host x.1.2.6 any 
SW1(config-ext-nacl)#permit ip host x.1.2.7 any 
SW1(config-ext-nacl)#deny ip any any 
SW1(config-ext-nacl)#exit 
SW1(config)#ip pim accept-register list PIM_REGISTER_FILTER 
SW1(config)#end 

Step 2: Configure the RP to rate limit the number of multicast register messages. 

SW1(config)#ip pim register-rate-limit nn 

Step 3: Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers. 

SW1(config)#ip access-list extended EXTERNAL_ACL_INBOUND 
SW1(config-ext-nacl)#permit tcp any any established 
SW1(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639 
SW1(config-ext-nacl)#deny tcp any host x.1.28.8 eq 639 
SW1(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp 
SW1(config-ext-nacl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8 
SW1(config-ext-nacl)#permit pim host x.1.28.2 host x.1.28.8 
… 
… 
… 
SW1(config-ext-nacl)#deny ip any any'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22771r507600_chk'
  tag severity: 'low'
  tag gid: 'V-221056'
  tag rid: 'SV-221056r863379_rule'
  tag stig_id: 'CISC-RT-000820'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-22760r507601_fix'
  tag 'documentable'
  tag legacy: ['SV-110933', 'V-101829']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
