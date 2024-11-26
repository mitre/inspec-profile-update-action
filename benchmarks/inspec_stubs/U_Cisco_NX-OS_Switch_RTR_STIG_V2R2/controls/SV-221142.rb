control 'SV-221142' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network switches presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled switch. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP switches must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the switch configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Step 1: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example below:

interface Ethernet2/3
 no switchport
 ip access-group EXTERNAL_ACL_INBOUND in
 ip address x.1.28.8/24
 ip pim sparse-mode

Step 2: Verify that the ACL restricts MSDP peering to only known sources.

ip access-list EXTERNAL_ACL_INBOUND
 10 permit tcp any any established 
 20 permit tcp x.1.28.2/32 x.1.28.8/32 eq 639 
 30 deny tcp any x.1.28.8/32 eq 639 log 
 40 permit tcp x.1.28.2/32 10.x.28.8/32 eq bgp 
 50 permit tcp x.1.28.2/32 eq bgp x.1.28.8/32 
 60 permit pim x.1.28.2/32 x.1.28.8/32 
…
 …
 …
120 deny ip any any log

Note: MSDP connections are via TCP port 639.

If the switch is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers.

SW1(config)# ip access-list EXTERNAL_ACL_INBOUND
SW1(config-acl) # permit tcp any any established
SW1(config-acl) # permit tcp host x.1.28.2 host x.1.28.8 eq 639
SW1(config-acl) # deny tcp any host x1.28.8 eq 639
SW1(config-acl) # permit tcp host x.1.28.2 host x.1.28.8 eq bgp
SW1(config-acl) # permit tcp host x.1.28.2 eq bgp host x.1.28.8
SW1(config-acl) # permit pim host x.1.28.2 host x.1.28.8
…
…
…
SW1(config-acl)# deny ip any any'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22857r409915_chk'
  tag severity: 'medium'
  tag gid: 'V-221142'
  tag rid: 'SV-221142r856654_rule'
  tag stig_id: 'CISC-RT-000900'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-22846r409916_fix'
  tag 'documentable'
  tag legacy: ['SV-111177', 'V-102221']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
