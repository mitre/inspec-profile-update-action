control 'SV-216810' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'The Cisco router does not have a mechanism to limit the multicast forwarding cache. However, the risk associated with this requirement can be fully mitigated by configuring the router to:

1. Filter PIM register messages.
2. Rate limiting the number of PIM register messages.
3. Accept MSDP packets only from known MSDP peers.

Step 1:  Verify that the RP router is configured to filter PIM register messages for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

ipv4 access-list PIM_REGISTER_FILTER
 10 deny ipv4 any 239.5.0.0 0.0.255.255
 20 permit ipv4 host 10.1.2.6 any
 30 permit ipv4 host 10.1.2.7 any
 40 deny ipv4 any any 
…
…
…
router pim
 address-family ipv4
  rp-address 2.2.2.2
  accept-register PIM_REGISTER_FILTER

Step 2: Verify that the router is configured to rate limiting the number of PIM register messages as shown in the example below.

router pim
 address-family ipv4
  allow-rp group-list FILTER_PIM_JOINS
  rp-address 10.2.2.2
  accept-register PIM_REGISTER_FILTER
  maximum register-states 250

Note: The maximum register-states command is used to set an upper limit for PIM register states. When the limit is reached, PIM discontinues route creation from PIM register messages. If not configured, the default is 2000 which would be an overage for a small to average size multicast deployment.

Step 3: Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers as shown in the example below.

Step 3a: Determine which interfaces would be peering MSDP with an external router by the configured peer addresses as shown in the example below.

router msdp
 peer x.14.2.1
  remote-as nn
 !
 peer x.15.3.5
  remote-as nn
 !
!

Step 3b: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example.

interface GigabitEthernet0/0/0/1
 ipv4 address x.14.2.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

Step 3c: Verify that the ACL restricts MSDP peering to only known sources.

ipv4 access-list EXTERNAL_ACL_INBOUND
 10 permit tcp host x.1.28.2 host x.1.28.8 eq 639
 20 deny tcp any host x.1.28.8 eq 639 log
 30 permit tcp host x.1.28.2 host x.1.28.8 eq bgp
 40 permit tcp host x.1.28.2 eq bgp host x.1.28.8
 50 permit pim host x.1.28.2 host x.1.28.8
 60 permit tcp any any established
 …
 …
 …
 140 deny ipv4 any any log

Note: MSDP connections is via TCP port 639

If the RP router is not configured to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers, this is a finding.'
  desc 'fix', 'The risk associated with this requirement can be fully mitigated by configuring the router to filter PIM register messages, rate limiting the number of PIM register messages, and accept MSDP packets only from known MSDP peers.

Step 1: Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

RP/0/0/CPU0:R2(config)#ipv4 access-list PIM_REGISTER_FILTER
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any 239.5.0.0 0.0.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 host 10.1.2.6 any
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 host 10.1.2.7 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#accept-register PIM_REGISTER_FILTER
RP/0/0/CPU0:R2(config-pim-default-ipv4)#end  

Step 2: Configure the RP to rate limit the number of multicast register messages.

RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#maximum register-states 250
RP/0/0/CPU0:R2(config-pim-default-ipv4)#end

Step 3: Configure the receive path or interface ACLs to only accepts MSDP packets from known MSDP peers.

RP/0/0/CPU0:R2(config)#ipv4 access-list EXTERNAL_ACL_INBOUND
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639
RP/0/0/CPU0:R2(config-ipv4-acl)#deny tcp any host x.1.28.8 eq 639 log
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8
RP/0/0/CPU0:R2(config-ipv4-acl)#permit pim host x.1.28.2 host x.1.28.8
RP/0/0/CPU0:R2(config-ipv4-acl)#permit tcp any any established
…
…
…
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ip any any log'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18042r288804_chk'
  tag severity: 'low'
  tag gid: 'V-216810'
  tag rid: 'SV-216810r531087_rule'
  tag stig_id: 'CISC-RT-000820'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-18040r288805_fix'
  tag 'documentable'
  tag legacy: ['SV-105965', 'V-96827']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
