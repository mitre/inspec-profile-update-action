control 'SV-216627' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM join messages for any undesirable multicast groups. In the example below, groups from 239.8.0.0/16 are not allowed.

ip pim rp-address 10.2.2.2
ip pim accept-rp 10.2.2.2 FILTER_PIM_JOINS
…
…
…
ip access-list standard FILTER_PIM_JOINS
 deny   239.8.0.0 0.0.255.255
 permit any
!

If the RP is not configured to filter join messages received from the DR for any undesirable multicast groups, this is a finding.'
  desc 'fix', 'Configure the RP to filter PIM join messages for any undesirable multicast groups as shown in the example below.

R2(config)#ip access-list standard PIM_JOIN_FILTER
R2(config-std-nacl)#deny 239.8.0.0 0.0.255.255
R2(config-std-nacl)#permit any
R2(config-std-nacl)#exit
R2(config)#ip pim accept-rp 10.2.2.2 PIM_JOIN_FILTER 
R2(config)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS Router RTR'
  tag check_id: 'C-17862r287250_chk'
  tag severity: 'low'
  tag gid: 'V-216627'
  tag rid: 'SV-216627r531085_rule'
  tag stig_id: 'CISC-RT-000840'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-17858r287251_fix'
  tag 'documentable'
  tag legacy: ['SV-105791', 'V-96653']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
