control 'SV-221074' do
  title 'The Cisco switch must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue switch could send a fictitious routing update to convince a site's perimeter switch to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor switch authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the switch configuration. For every routing protocol that affects the routing or forwarding tables, verify that neighbor switch authentication is encrypting the authentication key as shown in the examples below:

BGP Example

router bgp 1
 router-id 1.1.1.1
 address-family ipv4 unicast
 neighbor 10.1.12.2 remote-as 2
 password 3 3ec66c90c104ad13

Note: BGP authentication uses MD5. 

EIGRP Example

interface Ethernet2/21
 no switchport
 ip router eigrp 1
 ip authentication mode eigrp 1 md5

or

router eigrp 1
 authentication mode md5

Note: Interface authentication overrides process authentication.

IS-IS Example

interface Ethernet2/20
 no switchport
 isis authentication-type md5 level-1

OSPF Example

interface Ethernet2/2
 no switchport
 mac-address 0000.0000.002f
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 3 3ec66c90c104ad13

RIP Example

interface Ethernet2/8
 no switchport
 ip rip authentication mode md5

If the routing protocol is not encrypting the authentication key, this is a finding.'
  desc 'fix', 'Configure all routing protocol authentications to encrypt the authentication key.

BGP Example

SW1(config)#switch bgp nn
SW1(config-switch)#neighbor x.x.x.x password xxxxxx

EIGRP Example

SW1(config)# router eigrp 1
SW1(config-router)# authentication mode md5
SW1(config-router)# end

or

Authentication for the EIGRP neighbor

SW1(config)# int e2/21
SW1(config-if)# ip authentication mode eigrp 1 md5 
SW1(config-if)# end

Note: Interface authentication overrides process authentication.

IS-IS Example

SW1(config)# int e2/20
SW1(config-if)# isis authentication-type md5 level-1

OSPF Example

SW1(config)# int e2/2
SW1(config-if)# ip ospf authentication message-digest 
SW1(config-if)# ip ospf message-digest-key 1 md5 xxxxxxxxxxx

RIP Example

SW1(config)# int e2/8
SW1(config-if)# ip rip authentication mode md5'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22789r409711_chk'
  tag severity: 'medium'
  tag gid: 'V-221074'
  tag rid: 'SV-221074r622190_rule'
  tag stig_id: 'CISC-RT-000040'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-22778r409712_fix'
  tag 'documentable'
  tag legacy: ['SV-110967', 'V-101863']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
