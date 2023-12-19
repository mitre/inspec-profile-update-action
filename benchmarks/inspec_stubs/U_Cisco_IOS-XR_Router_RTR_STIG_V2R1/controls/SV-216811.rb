control 'SV-216811' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

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

If the RP router peering with PIM-SM routers is not configured with a policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

RP/0/0/CPU0:R2(config)#ipv4 access-list PIM_REGISTER_FILTER
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any 239.5.0.0 0.0.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 host 10.1.2.6 any
RP/0/0/CPU0:R2(config-ipv4-acl)#permit ipv4 host 10.1.2.7 any
RP/0/0/CPU0:R2(config-ipv4-acl)#deny ipv4 any any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#accept-register PIM_REGISTER_FILTER
RP/0/0/CPU0:R2(config-pim-default-ipv4)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18043r288807_chk'
  tag severity: 'low'
  tag gid: 'V-216811'
  tag rid: 'SV-216811r531087_rule'
  tag stig_id: 'CISC-RT-000830'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-18041r288808_fix'
  tag 'documentable'
  tag legacy: ['V-96829', 'SV-105967']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
