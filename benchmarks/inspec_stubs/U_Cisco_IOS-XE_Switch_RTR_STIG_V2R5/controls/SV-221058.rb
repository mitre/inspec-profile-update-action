control 'SV-221058' do
  title 'The Cisco multicast Rendezvous Point (RP) switch must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Cisco switch (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP is configured to filter PIM join messages for any undesirable multicast groups. In the example below, groups from 239.8.0.0/16 are not allowed.

ip pim rp-address 10.2.2.2
ip pim accept-rp 10.2.2.2 FILTER_PIM_JOINS
…
…
…
ip access-list standard FILTER_PIM_JOINS
 deny 239.8.0.0 0.0.255.255
 permit any
!

If the RP is not configured to filter join messages received from the DR for any undesirable multicast groups, this is a finding.'
  desc 'fix', 'Configure the RP to filter PIM join messages for any undesirable multicast groups as shown in the example below:

SW2(config)#ip access-list standard PIM_JOIN_FILTER
SW2(config-std-nacl)#deny 239.8.0.0 0.0.255.255
SW2(config-std-nacl)#permit any
SW2(config-std-nacl)#exit
SW2(config)#ip pim accept-rp 10.2.2.2 PIM_JOIN_FILTER 
SW2(config)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22773r408968_chk'
  tag severity: 'low'
  tag gid: 'V-221058'
  tag rid: 'SV-221058r622190_rule'
  tag stig_id: 'CISC-RT-000840'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-22762r408969_fix'
  tag 'documentable'
  tag legacy: ['SV-110937', 'V-101833']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
