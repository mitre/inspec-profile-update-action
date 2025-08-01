control 'SV-216812' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM join messages for any undesirable multicast groups. In the example below, groups from 239.8.0.0/16 are no allowed.

ipv4 access-list FILTER_PIM_JOINS
 10 deny ipv4 239.8.0.0 0.0.255.255 any
 20 permit ipv4 any any
…
…
…
router pim
 address-family ipv4
  allow-rp group-list FILTER_PIM_JOINS

If the RP is not configured to filter join messages received from the DR for any undesirable multicast groups, this is a finding.'
  desc 'fix', 'Configure the RP to filter PIM join messages for any undesirable multicast groups as shown in the example below.

RP/0/0/CPU0:R2(config)#ipv4 access-list FILTER_PIM_JOINS
RP/0/0/CPU0:R2(config-ipv4-acl)#deny 239.8.0.0 0.0.255.255
RP/0/0/CPU0:R2(config-ipv4-acl)#permit any
RP/0/0/CPU0:R2(config-ipv4-acl)#exit
RP/0/0/CPU0:R2(config)#router pim
RP/0/0/CPU0:R2(config-pim)#address-family ipv4
RP/0/0/CPU0:R2(config-pim-default-ipv4)#allow-rp group-list FILTER_PIM_JOINS 
RP/0/0/CPU0:R2(config-pim-default-ipv4)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18044r288810_chk'
  tag severity: 'low'
  tag gid: 'V-216812'
  tag rid: 'SV-216812r531087_rule'
  tag stig_id: 'CISC-RT-000840'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-18042r288811_fix'
  tag 'documentable'
  tag legacy: ['SV-105969', 'V-96831']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
