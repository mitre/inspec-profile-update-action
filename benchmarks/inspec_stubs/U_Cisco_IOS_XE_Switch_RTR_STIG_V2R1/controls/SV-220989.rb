control 'SV-220989' do
  title 'The Cisco switch must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue switch could send a fictitious routing update to convince a site's perimeter switch to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor switch authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the switch configuration. For every routing protocol that affects the routing or forwarding tables, verify that the switch is encrypting the authentication key as shown in the examples below:

BGP Example:

router bgp nn
 no synchronization
 bgp log-neighbor-changes
 neighbor x.x.x.x remote-as nn
 neighbor x.x.x.x password xxxxxxx

Note: BGP authentication uses MD5.

EIGRP Example:

interface GigabitEthernet1/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 EIGRP_KEY_CHAIN

IS-IS Example:

interface GigabitEthernet1/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip router isis
 isis authentication mode md5
 isis authentication key-chain ISIS_KEY_CHAIN

OSPF Example:

interface GigabitEthernet1/0
 no switchport
 ip address x.x.x.x 255.255.255.0
 ip ospf authentication message-digest
 ip ospf message-digest-key 1 md5 xxxxxx

RIP Example:

interface GigabitEthernet1/0
 no switchport
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_KEY_CHAIN

If the routing protocol is not encrypting the authentication key, this is a finding.'
  desc 'fix', 'Configure all routing protocol authentications to encrypt the authentication key.

BGP Example:

SW1(config)#router bgp nn
SW1(config-switch)#neighbor x.x.x.x password xxxxxx

EIGRP Example:

SW2(config)#int g0/1
SW2(config-if)#ip authentication mode eigrp 1 md5
SW2(config-if)#ip authentication key-chain eigrp 1 EIGRP_KEY_CHAIN

IS-IS Example:

SW1(config)#int g0/1
SW1(config-if)#isis authentication mode md5
SW1(config-if)#isis authentication key-chain ISIS_KEY_CHAIN

OSPF Example:

SW1(config)#int g1/0
SW1(config-if)#ip ospf authentication message-digest
SW1(config-if)#ip ospf message-digest-key 1 md5 xxxxxx

RIP Example:

SW2(config)#int g1/0
SW2(config-if)#ip rip authentication mode md5
SW2(config-if)#ip rip authentication key-chain RIP_KEY_CHAIN'
  impact 0.5
  ref 'DPMS Target Cisco IOS-XE Switch RTR'
  tag check_id: 'C-22704r408761_chk'
  tag severity: 'medium'
  tag gid: 'V-220989'
  tag rid: 'SV-220989r622190_rule'
  tag stig_id: 'CISC-RT-000040'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-22693r408762_fix'
  tag 'documentable'
  tag legacy: ['SV-110799', 'V-101695']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
