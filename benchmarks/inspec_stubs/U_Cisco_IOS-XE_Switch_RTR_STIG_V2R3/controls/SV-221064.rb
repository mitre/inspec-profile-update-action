control 'SV-221064' do
  title 'The Cisco Multicast Source Discovery Protocol (MSDP) switch must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network switches presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled switch. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP switches must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the switch configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Step 1: Verify that interfaces used for MSDP peering have an inbound ACL as shown in the example below:

interface GigabitEthernet1/1
 no switchport
 ip address x.1.28.8 255.255.255.0
 ip access-group EXTERNAL_ACL_INBOUND in
 ip pim sparse-mode

Step 2: Verify that the ACL restricts MSDP peering to only known sources.

ip access-list extended EXTERNAL_ACL_INBOUND
 permit tcp any any established
 permit tcp host x.1.28.2 host x.1.28.8 eq 639
 deny tcp any host x.1.28.8 eq 639 log
 permit tcp host x.1.28.2 host 10.1.28.8 eq bgp
 permit tcp host x.1.28.2 eq bgp host x.1.28.8
 permit pim host x.1.28.2 host x.1.28.8
…
 …
 …
deny ip any any log

Note: MSDP connections is via TCP port 639.

If the switch is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Configure the receive path or interface ACLs to only accept MSDP packets from known MSDP peers.

SW1(config)#ip access-list extended EXTERNAL_ACL_INBOUND
SW1(config-ext-nacl)#permit tcp any any established
SW1(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq 639
SW1(config-ext-nacl)#deny tcp any host x1.28.8 eq 639
SW1(config-ext-nacl)#permit tcp host x.1.28.2 host x.1.28.8 eq bgp
SW1(config-ext-nacl)#permit tcp host x.1.28.2 eq bgp host x.1.28.8
SW1(config-ext-nacl)#permit pim host x.1.28.2 host x.1.28.8
…
…
…
SW1(config-ext-nacl)#deny ip any any'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22779r408986_chk'
  tag severity: 'medium'
  tag gid: 'V-221064'
  tag rid: 'SV-221064r856427_rule'
  tag stig_id: 'CISC-RT-000900'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-22768r408987_fix'
  tag 'documentable'
  tag legacy: ['SV-110949', 'V-101845']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
