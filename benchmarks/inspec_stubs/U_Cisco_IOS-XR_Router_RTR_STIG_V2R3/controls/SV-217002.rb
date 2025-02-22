control 'SV-217002' do
  title 'The Cisco router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack", and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information. This includes BGP, RIP, OSPF, EIGRP, IS-IS and LDP.)
  desc 'check', 'Review the router configuration. Verify that the neighbor router authentication is enabled for all routing protocols. The configuration examples below depicts OSPF, EIGRP, IS-IS and BGP authentication.

BGP Example

router bgp nn
 address-family ipv4 unicast
 !
 neighbor x.1.23.2
  remote-as nn
  keychain BGP_KEY_CHAIN
  address-family ipv4 unicaast

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

If authentication is not enabled on all routing protocols, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables. The example configuration commands below enables OSPF, EIGRP, IS-IS, and BGP authentication.

BGP Example

RP/0/0/CPU0:R2(config)#router bgp nn
RP/0/0/CPU0:R2(config-bgp)#neighbor x.1.23.3 keychain BGP_KEY_CHAIN

EIGRP Example

RP/0/0/CPU0:R3(config)#router eigrp 1
RP/0/0/CPU0:R3(config-eigrp)#address-family ipv4
RP/0/0/CPU0:R3(config-eigrp-af)#int g0/0/0/0
RP/0/0/CPU0:R3(config-eigrp-af-if)#authentication keychain EIGRP_KEY_CHAIN
RP/0/0/CPU0:R3(config-eigrp-af-if)#end

IS-IS Example

RP/0/0/CPU0:R2(config)#router isis 1
RP/0/0/CPU0:R2(config-isis)#lsp-password keychain ISIS_KEY_CHAIN
RP/0/0/CPU0:R2(config-isis)#int GigabitEthernet0/0/0/2
RP/0/0/CPU0:R2(config-isis-if)#hello-password keychain ISIS_KEY_CHAIN
RP/0/0/CPU0:R2(config-isis-if)#end

OSPF Example

RP/0/0/CPU0:R3(config)#router ospf 1
RP/0/0/CPU0:R3(config-ospf)#area 0
RP/0/0/CPU0:R3(config-ospf-ar)#authentication message-digest keychain OSPF_KEY_CHAIN
RP/0/0/CPU0:R3(config-ospf-ar)#end

RIP Example

RP/0/0/CPU0:R2(config)#router rip
RP/0/0/CPU0:R2(config-rip)#int g0/0/0/2
RP/0/0/CPU0:R2(config-rip-if)#authentication keychain XXX_KEY_CHAIN mode md5
RP/0/0/CPU0:R2(config-rip-if)#end'
  impact 0.5
  ref 'DPMS Target Cisco IOS XR Router RTR'
  tag check_id: 'C-18232r288846_chk'
  tag severity: 'medium'
  tag gid: 'V-217002'
  tag rid: 'SV-217002r856457_rule'
  tag stig_id: 'CISC-RT-000020'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-18230r288847_fix'
  tag 'documentable'
  tag legacy: ['SV-105817', 'V-96679']
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
