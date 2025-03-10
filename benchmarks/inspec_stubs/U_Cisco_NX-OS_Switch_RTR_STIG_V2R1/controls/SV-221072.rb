control 'SV-221072' do
  title 'The Cisco switch must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue switch could send a fictitious routing update to convince a site's perimeter switch to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor switch authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the switch configuration. Verify that neighbor switch authentication is enabled for all routing protocols. The configuration examples below depicts BGP, EIGRP, IS-IS and OSPF authentication.

BGP Example

router bgp 1
 router-id 1.1.1.1
 address-family ipv4 unicast
 neighbor 10.1.12.2 remote-as 2
 password 3 3ec66c90c104ad13

EIGRP Example

key chain EIGRP_KEY
 key 1
 key-string xxxxxxx
…
…
…
interface Ethernet2/21
 no switchport
 ip router eigrp 1
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 EIGRP_KEY

or

router eigrp 1
 authentication mode md5
 authentication key-chain EIGRP_KEY

Note: Interface authentication overrides process authentication.

IS-IS Example

interface Ethernet2/20
 no switchport
 isis authentication-type md5 level-1
 isis authentication key-chain xxxxx level-1
 ip router isis 1

OSPF Example

interface Ethernet2/2
 no switchport
 ip ospf authentication
 ip ospf authentication key-chain OSPF_KEY
 ip router ospf 1 area 0.0.0.0

RIP Example

interface Ethernet2/8
 no switchport
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_KEY

If authentication is not enabled on all routing protocols, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables.

The example configuration commands below enable OSPF, EIGRP, IS-IS, and BGP authentication.

BGP Example

SW1(config)# switch bgp nn
SW1(config-router)# neighbor 10.1.12.2
SW1(config-router-neighbor)# password xxxxxxxx
SW1(config-router-neighbor)# end

EIGRP Example

Step 1: Configure the key chain. 

SW1(config)# key chain EIGRP_KEY 
SW1(config-keychain)# key 1 
SW1(config-keychain-key)# key-string xxxxxx
SW1(config-keychain-key)# exit
SW1(config-keychain)# exit

Step 2: Apply the key chain to the EIGRP process or each neighbor.

Authentication for the EIGRP process

SW1(config)# router eigrp 1
SW1(config-router)# authentication mode md5
SW1(config-router)# authentication key-chain XXXXXX
SW1(config-router)# end

or

Authentication for the EIGRP neighbor

SW1(config)# int e2/21
SW1(config-if)# ip authentication mode eigrp 1 md5 
SW1(config-if)# ip authentication key-chain eigrp 1 xxxxx
SW1(config-if)# end

Note: Interface authentication overrides process authentication.

IS-IS Example

Step 1: Configure the key chain.

SW1(config)# key chain ISIS_KEY 
SW1(config-keychain)# key 1 
SW1(config-keychain-key)# key-string xxxxxx
SW1(config-keychain-key)# exit
SW1(config-keychain)# exit

Step 2: Apply the key chain to each ISIS neighbor.

SW1(config)# int e2/20
SW1(config-if)# isis authentication-type md5 level-1
SW1(config-if)# isis authentication key-chain xxxxx level-1 

OSPF Example

Step 1: Configure the key chain. 

SW1(config)# key chain OSPF_KEY 
SW1(config-keychain)# key 1 
SW1(config-keychain-key)# key-string xxxxxx
SW1(config-keychain-key)# exit
SW1(config-keychain)# exit

Step 2: Apply the key chain to each OSPF neighbor.

SW1(config)# int e2/2
SW1(config-if)# ip ospf authentication
SW1(config-if)# ip ospf authentication key-chain OSPF_KEY

RIP Example

Step 1: Configure the key chain. 

SW1(config)# key chain RIP_KEY 
SW1(config-keychain)# key 1 
SW1(config-keychain-key)# key-string xxxxxx
SW1(config-keychain-key)# exit
SW1(config-keychain)# exit

Step 2: Apply the key chain to each RIP neighbor.

SW1(config)# int e2/8
SW1(config-if)# ip rip authentication mode md5 
SW1(config-if)# ip rip authentication key-chain RIP_KEY'
  impact 0.5
  ref 'DPMS Target Cisco NX-OS Switch RTR'
  tag check_id: 'C-22787r539275_chk'
  tag severity: 'medium'
  tag gid: 'V-221072'
  tag rid: 'SV-221072r622190_rule'
  tag stig_id: 'CISC-RT-000020'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-22776r409706_fix'
  tag 'documentable'
  tag legacy: ['SV-110963', 'V-101859']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
