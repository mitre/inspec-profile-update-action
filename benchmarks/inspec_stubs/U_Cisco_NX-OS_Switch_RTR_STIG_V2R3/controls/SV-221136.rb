control 'SV-221136' do
  title 'The Cisco multicast Rendezvous Point (RP) switch must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated switch (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP switch is configured to filter PIM register messages. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

ip pim register-policy PIM_REGISTER_FILTER
…
…
…
route-map PIM_REGISTER_FILTER deny 10
 match ip multicast group 239.5.0.0/16 
route-map PIM_REGISTER_FILTER permit 20
 match ip multicast source x.1.2.6/32 
route-map PIM_REGISTER_FILTER permit 30
 match ip multicast source x.1.2.7/32 
route-map PIM_REGISTER_FILTER permit 40
 match ip multicast group-range 232.0.0.0 to 233.255.255.255 
route-map PIM_REGISTER_FILTER deny 50
 match ip multicast source 0.0.0.0/0

If the RP switch peering with PIM-SM switches is not configured with a policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the switch to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources. The example below will deny any multicast streams for groups 239.5.0.0/16 and allow from only sources x.1.2.6 and x.1.2.7. 

Step 1: Configure a route map to filter multicast groups and sources as shown in the example below:

SW1(config)# route-map PIM_REGISTER_FILTER deny 10 
SW1(config-route-map)# match ip multicast group 239.5.0.0/16 
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 20
SW1(config-route-map)# match ip multicast source x.1.2.6/32
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 30
SW1(config-route-map)# match ip multicast source x.1.2.7/32
SW1(config-route-map)# route-map PIM_REGISTER_FILTER permit 40
SW1(config-route-map)# match ip multicast group-range 232.0.0.0 to 233.255.255.255
SW1(config-route-map)# route-map PIM_REGISTER_FILTER deny 50
SW1(config-route-map)# match ip multicast source 0.0.0.0/0
SW1(config-route-map)# exit

Step 2: Configure a multicast register policy referencing the configured route map.

SW1(config)# ip pim register-policy PIM_REGISTER_FILTER
SW1(config)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22851r409897_chk'
  tag severity: 'low'
  tag gid: 'V-221136'
  tag rid: 'SV-221136r622190_rule'
  tag stig_id: 'CISC-RT-000830'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-22840r409898_fix'
  tag 'documentable'
  tag legacy: ['SV-111091', 'V-101987']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
