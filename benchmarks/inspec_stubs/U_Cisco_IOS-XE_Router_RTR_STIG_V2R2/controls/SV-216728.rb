control 'SV-216728' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Step 1: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example.

interface GigabitEthernet1/1
 ip address x.1.28.8 255.255.255.0
 ip access-group EXTERNAL_ACL_INBOUND in
 ip pim sparse-mode

Step 2: Verify that the ACL restricts MSDP peering to only known sources.

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

Note: MSDP connections is via TCP port 639.

If the router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers.

R8(config)#ip access-list extended EXTERNAL_ACL_INBOUND
R8(config-ext-nacl)#permit tcp any any established
R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639
R8(config-ext-nacl)#deny tcp any host x1.28.8 eq 639
R8(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp
R8(config-ext-nacl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8
R8(config-ext-nacl)#permit pim host x.1.28.2 host x.1.28.8
…
…
…
R8(config-ext-nacl)#deny ip any any'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17961r288126_chk'
  tag severity: 'medium'
  tag gid: 'V-216728'
  tag rid: 'SV-216728r531086_rule'
  tag stig_id: 'CISC-RT-000900'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-17959r288127_fix'
  tag 'documentable'
  tag legacy: ['SV-106167', 'V-97029']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
