control 'SV-254001' do
  title 'The Juniper router must be configured to use encryption for routing protocol authentication.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates. However, using clear-text authentication provides little benefit since an attacker can intercept traffic and view the authentication key. This would allow the attacker to use the authentication key in an attack.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration.

For every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor router authentication is encrypting the authentication key.

[edit protocols]
ospf {
    area <area number> {
        interface <interface name>.<logical unit> {
            authentication {
                md5 1 key "$8$aes256-gcm$hmac-sha2-256$100$hvt9Fpk6EEU$I2FKFJNrdKHpp1xesMB0aA$l9BsHxOYO4+B8f7erRj8Hw$A9PYzx53Ius"; ## SECRET-DATA
            }
        }
        interface <interface name>.<logical unit> {
           ipsec-sa <SA name>;
        }
    }
}
ospf3 {
    area <area number> {
        interface <interface name>.<logical unit> {
            ipsec-sa <SA name>;
        }
    }
}

Note: OSPFv3 only supports IPsec SA authentication; OSPFv2 supports both IPsec SA and MD5 authentication. MD5 authentication is only included to support devices that do not support IPsec SA authentication.

Verify the OSPFv3 SA.
[edit security ipsec]
security-association <SA name> {
    mode transport;
    manual {
        direction bidirectional {
            protocol (ah | esp | bundle);
            spi (256..16639); <<< The SPI is an integer value that must match the peer
            encryption {
                algorithm (hmac-sha1-96 | hmac-sha-256-128);
                key hexadecimal "$8$aes256-gcm$hmac-sha2-256$100$QAP67/2oV/s$nz+2A3zRz40fwxMJdbbA0Q$R5A/koX36OvUWBB543QwAA$tQrR3fkCL2oQ3V1O2Tw2lYl7THNuqBQ6hpyi8naLlXMaKQM0SdJYefQU41rB3zpjisVIWBwS+S8+O146luRf3Q"; ## SECRET-DATA
            }
        }
    }
}
Note: OSPFv3 SA uses manual transport mode encapsulating security payload (ESP) associations.

If authentication is not encrypting the authentication key, this is a finding.'
  desc 'fix', %q(Configure routing protocol authentication to encrypt the authentication key.

set protocols ospf area <area number> interface <interface name>.<logical unit> authentication md5 <key ID> key "<PSK>" 
-or-
set protocols ospf area <area number> interface <interface name>.<logical unit> ipsec-sa <SA name>

set protocols ospf3 area <area number> interface <interface name>.<logical unit> ipsec-sa <SA name>

set security ipsec security-association <SA name> mode transport
set security ipsec security-association <SA name> manual direction bidirectional protocol (ah | esp | bundle)
set security ipsec security-association <SA name> manual direction bidirectional spi <manually configured SPI (256..16639)>
set security ipsec security-association <SA name> manual direction bidirectional encryption algorithm (hmac-sha1-96 | hmac-sha-256-128)
set security ipsec security-association <SA name> manual direction bidirectional authentication key hexadecimal "<appropriate PSK>"
Note: Encryption keys can also be entered as ASCII with the keyword 'ascii-text' replacing 'hexadecimal'. Regardless of key type, the PSK is hashed in the configuration.)
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57453r844034_chk'
  tag severity: 'medium'
  tag gid: 'V-254001'
  tag rid: 'SV-254001r844036_rule'
  tag stig_id: 'JUEX-RT-000290'
  tag gtitle: 'SRG-NET-000168-RTR-000077'
  tag fix_id: 'F-57404r844035_fix'
  tag 'documentable'
  tag cci: ['CCI-000803']
  tag nist: ['IA-7']
end
