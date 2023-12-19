control 'SV-216994' do
  title 'The Cisco router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information. This includes BGP, RIP, OSPF, EIGRP, IS-IS and LDP.)
  desc 'check', 'Review the router configuration. Verify that neighbor router authentication is enabled for all routing protocols. The configuration examples below depicts OSPF, EIGRP, IS-IS and BGP authentication.

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
 ip address x.x.x.x 255.255.255.0
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 EIGRP_KEY

IS-IS Example:

interface GigabitEthernet0/0
 ip address x.x.x.x 255.255.255.0
 ip router isis
 isis password xxxxxxx

OSPF Example:

interface GigabitEthernet0/0
 ip address x.x.x.x 255.255.255.0
 ip ospf authentication-key xxxxx

If authentication is not enabled on all routing protocols, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables.

The example configuration commands below enables BGP, EIGRP, IS-IS, and OSPF authentication.

BGP Example

R1(config)#router bgp nn
R1(config-router)#neighbor x.x.x.x password xxxxxx

EIGRP Example

R5(config)#key chain EIGRP_KEY
R5(config-keychain)#key 1
R5(config-keychain-key)#key-string xxxxx
R5(config-keychain-key)#exit
R5(config-keychain)#exit
R5(config)#int g0/0
R5(config-if)#ip authentication mode eigrp 1 md5
R5(config-if)#ip authentication key-chain eigrp 1 EIGRP_KEY
R5(config-if)#end

IS-IS Example

R5(config)#int g0/0
R5(config-if)#isis password xxxxxx

OSPF Example

R5(config)#int g0/0
R5(config-if)#ip ospf authentication-key xxxxx
R5(config-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-18224r288144_chk'
  tag severity: 'medium'
  tag gid: 'V-216994'
  tag rid: 'SV-216994r538970_rule'
  tag stig_id: 'CISC-RT-000020'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-18222r288145_fix'
  tag 'documentable'
  tag legacy: ['SV-105995', 'V-96857']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
