control 'SV-75377' do
  title 'The Arista Multilayer Switch must encrypt all methods of configured authentication for the OSPF routing protocol.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network, or merely used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack. 

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and Multicast-related protocols.)
  desc 'check', 'Review the router configuration for the following configuration statement under the interface configuration for any interface participating in the OSPF topology. SHA1 must be used instead of MD5 in all cases when that option is available.

ip ospf authentication message-digest
ip ospf message-digest-key [number] md5 [type] [key]

For IPv6 Authentication, one of the following statements must be present under the ipv6 router OSPF configuration statement, or on any interface running OSPFv3, depending on the type of encryption established. There are two methods of authentication for OSPFv3 in this scenario; the first uses authentication header (AH), and the second uses Authentication Header with Encapsulating Security Payload. OSPFv3 authentication can be configured for an interface or an area, and interface configuration will override area configuration. Users may configure a key or a passphrase.

interface ethernet1
ipv6 ospf authentication ipsec spi [spi number] [md5/sha1] [passphrase/key] [0/7] [passphrase/key]

OR

interface ethernet1
ipv6 ospf encryption ipsec spi [spi number] esp null [md5/sha1] [passphrase/key] [0/7] [passphrase/key] 

In an area configuration, the following text must be included under the "ipv6 router ospf [process ID]" configuration section.

ipv6 router ospf 200
area [area number] authentication ipsec spi [spi number] [md5/sha1] [passphrase/key] [0/7] [passphrase/key] 

OR for ESP

ipv6 router ospf 200
area 0 encryption ipsec spi [spi] esp null [md5/sha1] [0/7] [key] |
passphrase [0/7] [key]

If either of these statements is not present, OSPF is not using encryption for authentication, and this is a finding.'
  desc 'fix', 'Configure routing protocol authentication to encrypt the authentication key via the following commands under the interface configuration mode. SHA1 must be used instead of MD5 in all cases when that option is available.

ip ospf authentication message-digest
ip ospf message-digest-key [number] md5 [type] [key]

For IPv6 global configuration, enter:
ipv6 router ospf [process number]
area [area number] authentication ipsec spi [spi number] [md5/sha1] [passphrase/key] [0/7] [passphrase/key]

Alternatively, under the interface configuration mode, enter:
ipv6 ospf authentication ipsec spi [spi number] [md5/sha1] [passphrase/key] [0/7] [passphrase/key]

To use ESP encryption on AH headers, instead enter:
ipv6 router ospf [process number]
area [area number] encryption ipsec spi [spi number] esp null [md5/sha1] [passphrase/key] [0/7] [passphrase/key] 

or on an interface:
ipv6 ospf encryption ipsec spi [spi number] esp null [md5/sha1] [passphrase/key] [0/7] [passphrase/key]'
  impact 0.5
  ref 'DPMS Target Arista DCS-7000 series RTR'
  tag check_id: 'C-61865r2_chk'
  tag severity: 'medium'
  tag gid: 'V-60919'
  tag rid: 'SV-75377r2_rule'
  tag stig_id: 'AMLS-L3-000250'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-66631r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
