control 'SV-216644' do
  title 'The Cisco router must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration. For every routing protocol that affects the routing or forwarding tables, verify that neighbor router authentication is encrypting the authentication key as shown in the examples below.

BGP Example:

key chain <KEY-CHAIN-NAME> tcp 
 key <KEY-ID>
  send-id <ID>
  recv-id <ID>
   cryptographic-algorithm hmac-sha-1
  key-string <KEY>
   accept-lifetime 00:00:00 Jan 1 2022 duration 180
   send-lifetime 00:00:00 Jan 1 2022 duration 180 
!
!
router bgp <ASN>
 no synchronization
 bgp log-neighbor-changes
 neighbor x.x.x.x remote-as <ASN>
 neighbor x.x.x.x ao <KEY-CHAIN-NAME> 

Note: BGP uses key chains and TCP-AO to replace MD5.

EIGRP Example:

interface GigabitEthernet1/0
 ip address x.x.x.x 255.255.255.0
 ip authentication mode eigrp 1 md5
 ip authentication key-chain eigrp 1 EIGRP_KEY_CHAIN

IS-IS Example:

interface GigabitEthernet1/0
 ip address x.x.x.x 255.255.255.0
 ip router isis
 isis authentication mode md5
 isis authentication key-chain ISIS_KEY_CHAIN

OSPF Example:

key chain OSPF_KEY_CHAIN
key 1
key-string xxxxxxx
cryptographic-algorithm hmac-sha-256
…
…
…
interface GigabitEthernet0/1
ip address x.x.x.x 255.255.255.0
ip ospf authentication key-chain OSPF_KEY_CHAIN

RIP Example:

interface GigabitEthernet1/0
 ip rip authentication mode md5
 ip rip authentication key-chain RIP_KEY_CHAIN

If the routing protocol is not encrypting the authentication key, this is a finding.'
  desc 'fix', 'Configure all routing protocol authentications to encrypt the authentication key.

BGP Example:

Step 1: Configure a keychain for TCP-AO.

key chain <KEY-CHAIN-NAME> tcp 
 key <KEY-ID>
  send-id <ID>
  recv-id <ID>
   cryptographic-algorithm hmac-sha-1
  key-string <KEY>
   accept-lifetime 00:00:00 Jan 1 2022 duration 180
   send-lifetime 00:00:00 Jan 1 2022 duration 180 
!

Step 2: Configure BGP autonomous system.

router bgp <ASN>
 no synchronization
 bgp log-neighbor-changes
 neighbor x.x.x.x remote-as <ASN>
 neighbor x.x.x.x ao <KEY-CHAIN-NAME> 

EIGRP Example:

R2(config)#int g0/1
R2(config-if)#ip authentication mode eigrp 1 md5
R2(config-if)#ip authentication key-chain eigrp 1 EIGRP_KEY_CHAIN

IS-IS Example:

R5(config)#int g0/1
R5(config-if)#isis authentication mode md5
R5(config-if)#isis authentication key-chain ISIS_KEY_CHAIN

OSPF Example:

R5(config)#key chain OSPF_KEY_CHAIN
R5(config-keychain)#key 1
R5(config-keychain-key)#key-string xxxxxx
R5(config-keychain-key)#cryptographic-algorithm hmac-sha-256
R5(config-keychain-key)#exit
R5(config-keychain-key)#end
R5(config)#interface GigabitEthernet0/2
R5(config-if)#ip ospf authentication key-chain OSPF_KEY_CHAIN

RIP Example:

R2(config)#int g1/0
R2(config-if)#ip rip authentication mode md5
R2(config-if)#ip rip authentication key-chain RIP_KEY_CHAIN'
  impact 0.5
  ref 'DPMS Target Cisco IOS XE Router RTR'
  tag check_id: 'C-17877r894616_chk'
  tag severity: 'medium'
  tag gid: 'V-216644'
  tag rid: 'SV-216644r894618_rule'
  tag stig_id: 'CISC-RT-000040'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-17875r894617_fix'
  tag 'documentable'
  tag legacy: ['SV-105999', 'V-96861']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
