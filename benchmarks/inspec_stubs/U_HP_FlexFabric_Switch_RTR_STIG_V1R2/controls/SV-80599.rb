control 'SV-80599' do
  title 'The HP FlexFabric Switch must enable neighbor authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the HP FlexFabric Switch configuration; for every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor HP FlexFabric Switch authentication is enabled.

If neighbor authentication for all router control plane protocols is not configured, this is a finding.

The information below shows OSPF and OSPFv3 authentication is enabled on interface gigabit ethernet 0/0

[HP] display current-configuration interface GigabitEthernet 0/0
#
interface GigabitEthernet0/0
 port link-mode route
 description R1 ACTIVE
 combo enable copper
 ip address 201.6.1.62 255.255.255.252
 ospf authentication-mode md5 1 cipher **********
 ospfv3 200 area 0.0.0.0
 ospfv3 ipsec-profile jitc
 ipv6 address 2115:B:1::3E/126'
  desc 'fix', 'The following example shows how to configure the network device to authenticate OSPF and OSPFv3 packets with its peers.

OSPF configuration:
[HP] ospf 200
[HP-ospf-200] area 0.0.0.0
[HP-ospf-200-area-0.0.0.0] authentication-mode md5 1 cipher *************
[HP-ospf-200-area-0.0.0.0] network 201.6.1.60 0.0.0.3

OSPFv3 Configuration
[HP] ospfv3 200
[HP-ospf-200] area 0.0.0.0

IPsec profile configuration for OSPFv3
[HP] ipsec profile jitc manual
[HP--ipsec-profile-manual-jitc] transform-set jitcipsecprop
[HP--ipsec-profile-manual-jitc] sa spi inbound esp 256
[HP--ipsec-profile-manual-jitc] sa string-key inbound esp simple 2!HPAdmin123123
[HP--ipsec-profile-manual-jitc] sa spi outbound esp 256
[HP--ipsec-profile-manual-jitc] sa string-key outbound esp simple 2!HPAdmin123123

Interface configuration

interface GigabitEthernet0/0
 port link-mode route
 description R1 ACTIVE
 combo enable copper
 ip address 201.6.1.62 255.255.255.252
 ospf authentication-mode md5 1 cipher $c$3$6v1tbSQA2aWAzrgzm36LZrBbmS+jUeg=
 ospfv3 200 area 0.0.0.0
 ospfv3 ipsec-profile jitc
 ipv6 address 2115:B:1::3E/126'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66755r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66109'
  tag rid: 'SV-80599r1_rule'
  tag stig_id: 'HFFS-RT-000010'
  tag gtitle: 'SRG-NET-000025-RTR-000020'
  tag fix_id: 'F-72185r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
