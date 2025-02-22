control 'SV-75371' do
  title 'The Arista Multilayer Switch must enable neighbor router authentication for control plane protocols except RIP.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the router configuration; for every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor router authentication is enabled.

For BGP, this can be verified via the "show running-config" command and validating that any configured neighbor has an associated password statement. For OSPF, under the interface configuration mode, verify the following statements are configured:

ip ospf authentication message-digest
ip ospf message-digest-key [number] md5 [type] [key]

For IS-IS, under the interface configuration mode, verify the following statements are configured:

isis authentication mode md5 [level-1|level-2]
isis authentication key [key-string] [level-1|level-2]

Alternatively, under “show isis interface” the authentication mode on the interface must show as being set to MD5.

Additionally, the global IS-IS router configuration must be set. From the output of “show isis summary” verify that the authentication mode for Level-1 and/or Level-2 as applicable, is set to MD5.

If authentication is not enabled for BGP, OSPF, and IS-IS, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables.

To configure BGP authentication, in the BGP configuration mode interface, when adding neighbors, include the following statement:

neighbor [ip address] password [type] [password]

For OSPF, under the interface configuration mode, enter the following commands:

ip ospf authentication message-digest
ip ospf authentication-key [type] [key] 

To Globally Configure IS-IS Authentication, use:
router isis [instance number] authentication mode md5 [level 1 | level 2] authentication key [0|7] [key string] [level 1 | level 2]

Where level 1 and level 2 variable specify the authentication to be used for each type or ISIS router, the ISIS instance number is the routing protocol instance, the variables 0 and 7 represent an encrypted or unencrypted key string, and the key string is the text for the encryption string. Global configuration authenticates ISIS LSPs, CSNPs and PSNPs. 

Interface configuration authenticates ISIS Hello PDUs, and is configured as such:

interface [ethernet | port-channel | vlan] [X] 
isis authentication mode md5 
isis authentication key [0|7] [text]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61859r2_chk'
  tag severity: 'medium'
  tag gid: 'V-60913'
  tag rid: 'SV-75371r2_rule'
  tag stig_id: 'AMLS-L3-000220'
  tag gtitle: 'SRG-NET-000025-RTR-000020'
  tag fix_id: 'F-66625r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
