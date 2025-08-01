control 'SV-216721' do
  title 'The Cisco multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial of service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

ip pim rp-address 10.1.12.3
ip pim accept-register list PIM_REGISTER_FILTER
…
…
…
ip access-list extended PIM_REGISTER_FILTER
 deny   ip any 239.5.0.0 0.0.255.255
 permit ip host 10.1.2.6 any
 permit ip host 10.1.2.7 any
 deny   ip any any

If the RP router peering with PIM-SM routers is not configured with a policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources 10.1.2.6 and 10.1.2.7. 

R2(config)#ip access-list extended PIM_REGISTER_FILTER
R2(config-ext-nacl)#deny ip any 239.5.0.0 0.0.255.255
R2(config-ext-nacl)#permit ip host 10.1.2.6 any
R2(config-ext-nacl)#permit ip host 10.1.2.7 any
R2(config-ext-nacl)#deny ip any any
R2(config-ext-nacl)#exit
R2(config)#ip pim accept-register list PIM_REGISTER_FILTER
R2(config)#end'
  impact 0.3
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17954r288105_chk'
  tag severity: 'low'
  tag gid: 'V-216721'
  tag rid: 'SV-216721r531086_rule'
  tag stig_id: 'CISC-RT-000830'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-17952r288106_fix'
  tag 'documentable'
  tag legacy: ['SV-106153', 'V-97015']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
