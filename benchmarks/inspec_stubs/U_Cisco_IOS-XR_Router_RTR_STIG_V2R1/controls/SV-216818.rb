control 'SV-216818' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. 

To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Step 1: Determine which interfaces would be peering MSDP with an external router by the configured peer addresses as shown in the example below.

router msdp
 peer x.14.2.1
  remote-as nn
 !
 peer x.15.3.5
  remote-as nn
 !
!

Step 2: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example.

interface GigabitEthernet0/0/0/1
 ipv4 address x.14.2.2 255.255.255.252
 ipv4 access-group EXTERNAL_ACL_INBOUND ingress

Step 3: Verify that the ACL restricts MSDP peering to only known sources.

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

If the router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Configure the interface ACLs to only accept MSDP packets from known MSDP peers.

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
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18050r288828_chk'
  tag severity: 'medium'
  tag gid: 'V-216818'
  tag rid: 'SV-216818r531087_rule'
  tag stig_id: 'CISC-RT-000900'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-18048r288829_fix'
  tag 'documentable'
  tag legacy: ['V-96843', 'SV-105981']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
