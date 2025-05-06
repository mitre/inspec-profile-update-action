control 'SV-256047' do
  title 'The Arista Multicast Source Discovery Protocol (MSDP) router must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'MSDP peering with customer network routers presents additional risks to the DISN Core, whether from a rogue or misconfigured MSDP-enabled router. To guard against an attack from malicious MSDP traffic, the receive path or interface filter for all MSDP-enabled RP routers must be configured to only accept MSDP packets from known MSDP peers.'
  desc 'check', 'Review the Arista router configuration to determine if there is a receive path or interface filter to only accept MSDP packets from known MSDP peers.

Step 1: Verify the MSDP peers and the corresponding interfaces.

router msdp
  peer 10.11.12.2
  !
  peer 10.22.12.2
  
Step 2: Verify the access-list is configured inbound on MSDP peering interfaces. MSDP uses TCP port 639. Execute the command "sh ip access-list".

ip access-list MSDP_FILTER
  10 permit tcp host 10.1.12.2 host 10.11.17.9 eq 639
  20 permit udp host 10.1.12.2 host 10.11.17.9 eq 500
  30 permit udp 10.11.17.9 eq 500 host 10.1.12.2
  40 deny ip any any log

Step 3: Verify the ACL is applied on the interface. Execute the command "sh run int ethernet YY".

interface ethernet 3
 ip access-group MSDP_FILTER in

If the Arista router is not configured to only accept MSDP packets from known MSDP peers, this is a finding.'
  desc 'fix', 'Ensure the receive path or interface filter for all Arista MSDP routers only accepts MSDP packets from known MSDP peers.

Step 1: Configure the MSDP peers.

LEAF-1A(config)#router msdp
LEAF-1A(config-router-msdp)#  peer 10.11.12.2
LEAF-1A(config-router-msdp)#  peer 10.22.12.2
  
Step 2: Configure the access-list inbound on MSDP peering interfaces. MSDP uses TCP port 639.

LEAF-1A(config-router-msdp-peer-10.22.12.2)#ip access-list MSDP_FILTER
LEAF-1A(config-acl-MSDP_FILTER)#  10 permit tcp host 10.1.12.2 host 10.11.17.9 eq 639
LEAF-1A(config-acl-MSDP_FILTER)#  20 permit udp host 10.1.12.2 host 10.11.17.9 eq 500
LEAF-1A(config-acl-MSDP_FILTER)#  30 permit udp 10.11.17.9 eq 500 host 10.1.12.2 
LEAF-1A(config-acl-MSDP_FILTER)#  40 deny ip any any log

Step 3: Apply the ACL on the interface.

LEAF-1A(config-acl-MSDP_FILTER)#interface ethernet 3
LEAF-1A(config-if-Et3)# ip access-group MSDP_FILTER in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59723r882481_chk'
  tag severity: 'medium'
  tag gid: 'V-256047'
  tag rid: 'SV-256047r882483_rule'
  tag stig_id: 'ARST-RT-000680'
  tag gtitle: 'SRG-NET-000364-RTR-000116'
  tag fix_id: 'F-59666r882482_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
