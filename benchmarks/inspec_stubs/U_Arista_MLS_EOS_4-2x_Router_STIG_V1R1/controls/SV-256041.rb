control 'SV-256041' do
  title 'The Arista perimeter router must be configured to block inbound packets with source Bogon IP address prefixes.'
  desc "Bogons include IP packets on the public internet that contain addresses that are not in any range allocated or delegated by the Internet Assigned Numbers Authority (IANA) or a delegated regional internet registry (RIR) and allowed for public internet use. Bogons also include multicast, IETF reserved, and special purpose address space as defined in RFC 6890.

Security of the internet's routing system relies on the ability to authenticate an assertion of unique control of an address block. Measures to authenticate such assertions rely on the validation the address block forms as part of an existing allocated address block, and must be a trustable and unique reference in the IANA address registries. The intended use of a Bogon address would only be for the purpose of address spoofing in denial-of-service attacks. Hence, it is imperative that IP packets with a source Bogon address are blocked at the network's perimeter."
  desc 'check', 'This requirement is not applicable for the DODIN backbone.

Verify the ingress filter is blocking packets with Bogon source addresses.

Review the Arista router configuration to verify it is configured to block IP packets with a Bogon source address with "show run | section prefix-list".

IPv4 Bogon Prefixes
0.0.0.0/8
10.0.0.0/8
100.64.0.0/10
127.0.0.0/8
169.254.0.0/16
172.16.0.0/12
192.0.0.0/24
192.0.2.0/24
192.88.99.0/24
192.168.0.0/16
198.18.0.0/15 |
198.51.100.0/24
203.0.113.0/24
224.0.0.0/4
240.0.0.0/4

IPv6 Bogon Prefixes
::/128
::1/128
0::/96
::ffff:0:0/96
3ffe::/16
64:ff9b::/96
100::/64
2001:10::/28
2001:db8::/32
2001:2::/48
2001::/32
2001::/23
2002::/16
fc00::/7
fe80::/10
fec0::/10
ff00::/8

If the Arista router is not configured to block inbound IP packets containing a Bogon source address, this is a finding.

Note: At a minimum, IP packets containing a source address from the special purpose address space as defined in RFC 6890 must be blocked. The 6Bone prefix (3ffe::/16) is also considered a Bogon address. Perimeter routers connected to commercial ISPs for internet or other non-DOD network sources must be reviewed for a full Bogon list.

Step 1: Verify the ACL is configured to block the IPv4 Bogon prefixes.

ip access-list BOGON_PREFIXES
deny ip 0.0.0.0/8 any
deny ip 10.0.0.0/8 any
deny ip 100.64.0.0/10 any
deny ip 127.0.0.0/8 any
deny ip 169.254.0.0/16 any
deny ip 172.16.0.0/12 any
deny ip 192.0.0.0/24 any
deny ip 192.0.2.0/24 any
deny ip 192.88.99.0/24 any
deny ip 192.168.0.0/16 any
deny ip 198.18.0.0/15 any
deny ip 198.51.100.0/24 any
deny ip 203.0.113.0/24 any
deny ip 224.0.0.0/4 any
deny ip 240.0.0.0/4 any

Step 2: Verify the ACL is configured to block the IPv6 Bogon prefixes.

ipv6 access-list BOGON_PREFIXES
deny ipv6 ::/128 any
deny ipv6 ::1/128 any
deny ipv6 0::/96 any
deny ipv6 ::ffff:0:0/96 any
deny ipv6 3ffe::/16 any
deny ipv6 64:ff9b::/96 any
deny ipv6 100::/64 any
deny ipv6 2001:10::/28 any
deny ipv6 2001:db8::/32 any
deny ipv6 2001:2::/48 any
deny ipv6 2001::/32 any
deny ipv6 2001::/23 any
deny ipv6 2002::/16 any
deny ipv6 fc00::/7 any
deny ipv6 fe80::/10 any
deny ipv6 fec0::/10 any
deny ipv6 ff00::/8 any

Step 3: Verify the IPv4 and IPv6 access lists are applied to the external interface.

interface ethernet 3
ip access-group BOGON_PREFIXES in
ipv6 access-group BOGON_PREFIXES in'
  desc 'fix', 'This requirement is not applicable for the DODIN backbone.

Configure the Arista router to block inbound packets with Bogon source addresses.

Step 1: Configure the ACL to block the IPv4 Bogon prefixes.

LEAF-1A(config)#ip access-list BOGON_PREFIXES
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 0.0.0.0/8 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 10.0.0.0/8 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 100.64.0.0/10 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 127.0.0.0/8 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 169.254.0.0/16 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 172.16.0.0/12 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 192.0.0.0/24 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 192.0.2.0/24 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 192.88.99.0/24 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 192.168.0.0/16 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 198.18.0.0/15 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 198.51.100.0/24 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 203.0.113.0/24 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 224.0.0.0/4 any
LEAF-1A(config-acl-BOGON_PREFIXES)#deny ip 240.0.0.0/4 any
LEAF-1A(config-acl-BOGON_PREFIXES)#exit

Step 2: Configure the ACL to block the ipv6 Bogon prefixes.

LEAF-1A(config)#ipv6 access-list BOGON_PREFIXES
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 ::/128 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 ::1/128 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 0::/96 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 ::ffff:0:0/96 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 3ffe::/16 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 64:ff9b::/96 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 100::/64 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2001:10::/28 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2001:db8::/32 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2001:2::/48 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2001::/32 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2001::/23 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 2002::/16 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 fc00::/7 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 fe80::/10 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 fec0::/10 any
LEAF-1A(config-ipv6-acl-BOGON_PREFIXES)#deny ipv6 ff00::/8 any

Step 3: Apply the IPv4 and IPv6 Bogon access lists to the external interface.

LEAF-1A(config)#interface ethernet 3
LEAF-1A(config-if-Et3)#ip access-group BOGON_PREFIXES in
LEAF-1A(config-if-Et3)#ipv6 access-group BOGON_PREFIXES in'
  impact 0.5
  ref 'DPMS Target Arista MLS EOS 4.2x RTR'
  tag check_id: 'C-59717r882463_chk'
  tag severity: 'medium'
  tag gid: 'V-256041'
  tag rid: 'SV-256041r882465_rule'
  tag stig_id: 'ARST-RT-000620'
  tag gtitle: 'SRG-NET-000364-RTR-000110'
  tag fix_id: 'F-59660r882464_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
