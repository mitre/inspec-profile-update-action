control 'SV-80601' do
  title 'The HP FlexFabric Switch must encrypt all methods of configured authentication for routing protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack. 

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Verify the HP FlexFabric Switch configuration to ensure that it is using a NIST validated FIPS 140-2 cryptography encryption mechanism by implementing OSPFv3 with IPsec.

[HP] display current-configuration interface

interface GigabitEthernet0/0
 port link-mode route
 description R1 ACTIVE
 combo enable copper
 ospfv3 200 area 0.0.0.0
 ospfv3 ipsec-profile jitc
 ipv6 address 2115:B:1::3E/126

If the routing protocol authentication mechanism is not a validated FIPS 140-2 cryptography, this is a finding.

Note: OSPFv3 requires IPsec to enable authentication using either the IPv6 Authentication Header (AH) or the Encapsulating Security Payload (ESP) header.'
  desc 'fix', 'Configure the HP FlexFabric Switch to authenticate OSPFv3 packets:

[HP]ipsec transform-set jitcipsecprop
[HP-ipsec-transform-set-jitcipsecprop] 
[HP-ipsec-transform-set-jitcipsecprop] ipsec transform-set jitcipsecprop
[HP-ipsec-transform-set-jitcipsecprop] encapsulation-mode transport
[HP-ipsec-transform-set-jitcipsecprop] esp encryption-algorithm aes-cbc-256
[HP-ipsec-transform-set-jitcipsecprop] esp authentication-algorithm sha1
[HP-ipsec-transform-set-jitcipsecprop] quit
[HP] ipsec profile jitc manual
[HP-ipsec-profile-manual-jitc]
[HP-ipsec-profile-manual-jitc] ipsec profile jitc manual
[HP-ipsec-profile-manual-jitc] transform-set jitcipsecprop
[HP-ipsec-profile-manual-jitc] sa spi inbound esp 256
[HP-ipsec-profile-manual-jitc] sa string-key inbound esp  simple test123
[HP-ipsec-profile-manual-jitc] sa spi outbound esp 256
[HP-ipsec-profile-manual-jitc] sa string-key outbound esp simple test123
[HP-ipsec-profile-manual-jitc] quit
[HP] interface gigabitethernet 0/1 
[HP--GigabitEthernet0/1] ospfv3 ipsec-profile jitc'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66757r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66111'
  tag rid: 'SV-80601r1_rule'
  tag stig_id: 'HFFS-RT-000011'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-72187r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
