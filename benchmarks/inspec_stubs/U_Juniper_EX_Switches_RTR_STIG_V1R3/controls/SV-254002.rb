control 'SV-254002' do
  title 'The Juniper router must be configured to authenticate all routing protocol messages using NIST-validated FIPS 198-1 message authentication code algorithm.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

Since MD5 is vulnerable to "birthday" attacks and may be compromised, routing protocol authentication must use FIPS 198-1 validated algorithms and modules to encrypt the authentication key. This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.

IP Security (IPsec) Security Association (SA) routing protocol authentication provides strong protection against unauthorized ("rogue") routing updates. IPsec SAs offer Authentication Header (AH) or Encapsulated Security Payload (ESP) to protect the routing updates. IPsec SA is required by newer routing protocols like OSPFv3 for authentication. IPsec SA routing protocol authentication supports FIPS 198-1 validated algorithms.)
  desc 'check', 'Verify routing protocol authentication is enabled using a FIPS 198-1 validated hashed message authentication code (HMAC).

For protocols supporting IPsec SA:
[edit security ipsec]
security-association <SA name> {
<snip>

NOTE: Versions of Junos not supporting RFC5709 must be configured to use MD5 authentication, but this is still a CAT III finding since MD5 is not compliant.
For protocols not supporting IPsec SA (OSPFv2 example shown)
[edit protocols ospf]
area <area number> {
    interface <name> {
        authentication {
            <algorithm> <key number> key “<hashed value>”;
        }
    }
}


If a NIST-validated FIPS 198-1 message authentication code algorithm is not being used to authenticate routing protocols, this is a finding.
Routing protocols using authentication with non-NIST-validated FIPS 198-1 algorithms may be downgraded to CAT III.'
  desc 'fix', %q(Configure routing protocol authentication to use a NIST-validated FIPS 198-1 message authentication code algorithm.

Configure the IPsec SA:
set security ipsec security-association <SA name> mode transport
set security ipsec security-association <SA name> manual direction bidirectional protocol (ah | esp | bundle)
set security ipsec security-association <SA name> manual direction bidirectional spi <manually configured SPI (256..16639)>
set security ipsec security-association <SA name> manual direction bidirectional authentication algorithm (hmac-sha1-96 | hmac-sha-256-128)
set security ipsec security-association <SA name> manual direction bidirectional authentication key hexadecimal "<appropriate PSK>"
Note: Encryption keys can also be entered as ASCII with the keyword 'ascii-text' replacing 'hexadecimal'. Regardless of key type, the PSK is hashed in the configuration.

Configure EGP / IGP to use IPsec SA for authentication:
set protocols bgp group <BGP group name> neighbor <IPv4 neighbor address> ipsec-sa <SA name>
set protocols bgp group <BGP group name> neighbor <IPv6 neighbor address> ipsec-sa <SA name>

set protocols ospf area <OSPFv2 area number> interface <interface name>.<logical unit> ipsec-sa <SA name>

set protocols ospf3 area <OSPFv3 area number> interface <interface name>.<logical unit> ipsec-sa <SA name>

NOTE: Versions of Junos not supporting RFC5709 must be configured to use MD5 authentication, but this is still a CAT III finding since MD5 is not compliant.)
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57454r904443_chk'
  tag severity: 'medium'
  tag gid: 'V-254002'
  tag rid: 'SV-254002r904444_rule'
  tag stig_id: 'JUEX-RT-000300'
  tag gtitle: 'SRG-NET-000168-RTR-000078'
  tag fix_id: 'F-57405r904414_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
