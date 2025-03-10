control 'SV-220987' do
  title 'The Cisco switch must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue switch could send a fictitious routing update to convince a site's perimeter switch to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor switch authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the switch configuration. Verify that authentication is enabled for all routing protocols. The configuration examples below depicts OSPF, EIGRP, IS-IS and BGP authentication.

BGP Example:

router bgp nn
 no synchronization
 bgp log-neighbor-changes
 neighbor x.x.x.x remote-as nn
 neighbor x.x.x.x password xxxxxxx

EIGRP Example:

key chain EIGRP_KEY
 key 1
 key-string xxxxxxx
…
…
…
interface GigabitEthernet0/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 EIGRP_KEY

IS-IS Example:

interface GigabitEthernet0/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip router isis
 isis password xxxxxxx

OSPF Example:

interface GigabitEthernet0/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip ospf authentication-key xxxxx

If authentication is not enabled on all routing protocols, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables. The example configuration commands below enables OSPF, EIGRP, IS-IS, and BGP authentication.

BGP Example:

SW1(config)#router bgp nn
SW1(config-switch)#neighbor x.x.x.x password xxxxxx

EIGRP Example:

SW1(config)#key chain EIGRP_KEY
SW1(config-keychain)#key 1
SW1(config-keychain-key)#key-string xxxxx
SW1(config-keychain-key)#exit
SW1(config-keychain)#exit
SW1(config)#int g0/0
SW1(config-if)#ip authentication mode eigrp 1 md5
SW1(config-if)#ip authentication key-chain eigrp 1 EIGRP_KEY
SW1(config-if)#end

IS-IS Example:

SW1(config)#int g0/0
SW1(config-if)#isis password xxxxxx

OSPF Example:

SW1(config)#int g0/0
SW1(config-if)#ip ospf authentication-key xxxxx
SW1(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22702r408755_chk'
  tag severity: 'medium'
  tag gid: 'V-220987'
  tag rid: 'SV-220987r856398_rule'
  tag stig_id: 'CISC-RT-000020'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-22691r408756_fix'
  tag 'documentable'
  tag legacy: ['SV-110795', 'V-101691']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
