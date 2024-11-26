control 'SV-216738' do
  title 'The Cisco router must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration. For every routing protocol that affects the routing or forwarding tables, verify that neighbor router authentication is encrypting the authentication key as shown in the examples below.

Step 1: Verify that the routing protocols are configured to use a key chain for authentication as shown in the examples below.

BGP Example

tcp ao 
 keychain BGP_KEY_CHAIN
  key <KEY-ID> SendID <ID> ReceiveID <ID>
 !
!
router bgp <ASN> 
 neighbor X.X.X.X
  remote-as <ASN>
  ao BGP_KEY_CHAIN
  address-family ipv4 unicast
!

EIGRP Example

router eigrp 1
 address-family ipv4
  interface GigabitEthernet0/0/0/2
   authentication keychain EIGRP_KEY_CHAIN

IS-IS Example

router isis 1
 net 49.0001.0001.0001.0002.00
 lsp-password keychain ISIS_KEY_CHAIN
 interface GigabitEthernet0/0/0/2
  hello-password keychain ISIS_KEY_CHAIN

OSPF Example

router ospf 1
 area 0
  authentication message-digest keychain OSPF_KEY_CHAIN

RIP Example

router rip
 interface GigabitEthernet0/0/0/2
  authentication keychain RIP_KEY_CHAIN mode md5

Step 2: Verify that the keys use an encryption algorithm as shown in the example below.

BGP Example

key chain BGP_KEY_CHAIN
 key <KEY-ID>
  accept-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  key-string <KEY VALUE>
  send-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  cryptographic-algorithm HMAC-SHA1-96
 !

OSPF Example

key chain OSPF_KEY_CHAIN
 key 1
  accept-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  key-string password 104300150004
  send-lifetime 01:00:00 january 01 2019 01:00:00 april 01 2019
  cryptographic-algorithm HMAC-SHA1-96
 !
 key 2
  accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  key-string password 030654090416
  send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
  cryptographic-algorithm HMAC-SHA1-96

If the routing protocol is not encrypting the authentication key, this is a finding.'
  desc 'fix', 'Configure the key chains used by the routing protocols to have the keys encrypted as shown in the example below. OSPF and BGP example shown, but others are configured similarly.

RP/0/0/CPU0:R2(config)#key chain OSPF_KEY_CHAIN
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN)#key 1
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#accept-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key-string password xxxxxxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#send-lifetime 01:00:00 jan 01 2019 01:00:00 april 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#cryptographic-algorithm HMAC-SHA1-96
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-1)#key 2
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#accept-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#key-string password xxxxxxxxxxxxxxx
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#send-lifetime 01:00:00 april 01 2019 01:00:00 july 01 2019 
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#cryptographic-algorithm HMAC-SHA1-96
RP/0/0/CPU0:R2(config-OSPF_KEY_CHAIN-2)#end

Configure BGP to use TCP-AO to replace MD5.

Configure Keychain for BGP 
RP/0/0/CPU0:R2(config)#key chain BGP_KEY_CHAIN 
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN)# key 1 
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN-1)#accept-lifetime 00:00:00 january 01 2022 infinite 
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN-1)#key-string password xxxxxxxxxxx
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN-1)#send-lifetime 00:00:00 january 01 2022 infinite
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN-1)#cryptographic-algorithm HMAC-SHA-256 
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN-1)#exit 
RP/0/RP0/CPU0:R2(config-BGP_KEY_CHAIN)#exit 
 
Configure TCP AO 
RP/0/0/CPU0:R2(config)#tcp ao 
RP/0/0/CPU0:R2(config-tcp-ao)#keychain BGP_KEY_CHAIN  
RP/0/0/CPU0:R2(config-tcp-ao-BGP_KEY_CHAIN)#key <KEY-ID> SendID <ID> ReceiveID <ID> 
RP/0/0/CPU0:R2(config-tcp-ao-BGP_KEY_CHAIN)#exit 
RP/0/0/CPU0:R2(config-tcp-ao)#exit

Configure BGP Neighbor to use TCP AO 
RP/0/RP0/CPU0:R2(config)#router bgp <ASN>  
RP/0/RP0/CPU0:R2(config-bgp)#neighbor X.X.X.X 
RP/0/RP0/CPU0:R2(config-bgp-nbr)#remote-as <ASN> 
RP/0/RP0/CPU0:R2(config-bgp-nbr)#ao BGP_KEY_CHAIN 
RP/0/RP0/CPU0:R2(config-bgp-nbr)#address-family ipv4 unicast 
RP/0/RP0/CPU0:R2(config-bgp-nbr)#exit 
RP/0/RP0/CPU0:R2(config-bgp)#exit 
RP/0/RP0/CPU0:R2(config)#commit'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-17970r894619_chk'
  tag severity: 'medium'
  tag gid: 'V-216738'
  tag rid: 'SV-216738r894621_rule'
  tag stig_id: 'CISC-RT-000040'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-17968r894620_fix'
  tag 'documentable'
  tag legacy: ['SV-105821', 'V-96683']
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
