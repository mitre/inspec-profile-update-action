control 'SV-221137' do
  title 'The Cisco multicast Rendezvous Point (RP) switch must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Cisco switch (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP switch is configured to filter PIM join messages for any undesirable multicast groups. In the example below, groups from 239.8.0.0/16 are not allowed.

route-map PIM_JOIN_FILTER deny 10
 match ip multicast group 239.0.0.0/8 
route-map PIM_JOIN_FILTER permit 20
 match ip multicast group 224.0.0.0/4 
…
…
…
interface Ethernet2/1
 no switchport
 ip address 10.1.12.1/24
 ip pim sparse-mode
 ip pim jp-policy PIM_JOIN_FILTER in

If the RP is not configured to filter join messages received from the DR for any undesirable multicast groups, this is a finding.'
  desc 'fix', 'Configure the RP to filter PIM join messages for any undesirable multicast groups as shown in the example below:

Step 1: Configure a PIM Join filter as shown in the example below:

SW1(config)# route-map PIM_JOIN_FILTER deny 
SW1(config-route-map)# match ip multicast group 239.8.0.0/8
SW1(config-route-map)# route-map PIM_JOIN_FILTER permit 20
SW1(config-route-map)# match ip multicast group 224.0.0.0/4
SW1(config-route-map)# exit

Step 2: Apply the PIM Join filter to the appropriate interfaces.

SW1(config)# int e2/1
SW1(config-if)# ip pim jp-policy PIM_JOIN_FILTER in
SW1(config-if)# end'
  impact 0.3
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22852r409900_chk'
  tag severity: 'low'
  tag gid: 'V-221137'
  tag rid: 'SV-221137r622190_rule'
  tag stig_id: 'CISC-RT-000840'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-22841r409901_fix'
  tag 'documentable'
  tag legacy: ['SV-111167', 'V-102211']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
