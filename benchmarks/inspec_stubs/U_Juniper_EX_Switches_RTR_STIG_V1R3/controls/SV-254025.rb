control 'SV-254025' do
  title 'The Juniper router must be configured to implement message authentication for all control plane protocols.'
  desc %q(A rogue router could send a fictitious routing update to convince a site's perimeter router to send traffic to an incorrect or even a rogue destination. This diverted traffic could be analyzed to learn confidential information about the site's network or used to disrupt the network's ability to communicate with other networks. This is known as a "traffic attraction attack" and is prevented by configuring neighbor router authentication for routing updates.

This requirement applies to all IPv4 and IPv6 protocols that are used to exchange routing or packet forwarding information; this includes all Interior Gateway Protocols (such as OSPF, EIGRP, and IS-IS) and Exterior Gateway Protocols (such as BGP), MPLS-related protocols (such as LDP), and multicast-related protocols.)
  desc 'check', 'Review the router configuration.

For every protocol that affects the routing or forwarding tables (where information is exchanged between neighbors), verify that neighbor router authentication is enabled.

[edit security ipsec]
security-association <sa name> {
    manual {
        direction bidirectional {
            protocol esp;
            spi <SPI value>;
            authentication {
                algorithm hmac-sha-256-128;
                key ascii-text "$8$aes256-gcm$hmac-sha2-256$100$SpJ/ERRFEsc$y1Wqf1zM3d3xI+ZVB9WzTw$lgM06LJZN3FcVbTaSkDz4g$bZVi57MkUWg"; ## SECRET-DATA
            }
        }
    }
}
[edit protocols]
bgp {
    group <group name> {
        type external;
        local-as <local AS number>;
        neighbor <neighbor 1 address> {
            authentication-key "$8$aes256-gcm$hmac-sha2-256$100$cFQ99Gy83Og$SCMVXvnfna7/cZqH9fCECQ$bCVokm+es94xFJONmbKFNA$4561Uc/r"; ## SECRET-DATA
        }
        neighbor <neighbor 2 address> {
            ipsec-sa <SA name>;
        }
    }
}

Note: Juniper BGP routers support either an MD5 key, rotating MD5 keys, or an IPsec security association (SA). Verify the PSK for each MD5 and SA is different between all neighbors.
ospf {
    area <area number> {
        interface <interface name>.<logical unit> {
            authentication {
                md5 1 key "$8$aes256-gcm$hmac-sha2-256$100$hvt9Fpk6EEU$I2FKFJNrdKHpp1xesMB0aA$l9BsHxOYO4+B8f7erRj8Hw$A9PYzx53Ius"; ## SECRET-DATA
            }
        }
        interface <interface name>.<logical unit> {
            interface-type p2p;
            ipsec-sa <SA name>;
        }                               
    }
}
Note: Juniper OSPF routers support either an MD5 key or an IPsec SA.
ospf3 {
    area <area number> {
        interface <interface name>.<logical unit> {
            ipsec-sa <SA name>;
        }
    }
}
Note: Juniper OSPFv3 routers only support IPsec SA.

If authentication is not enabled, this is a finding.'
  desc 'fix', 'Configure authentication to be enabled for every protocol that affects the routing or forwarding tables.

set security ipsec security-association <sa name> manual direction bidirectional protocol esp
set security ipsec security-association <sa name> manual direction bidirectional spi <SPI value>
set security ipsec security-association <sa name> manual direction bidirectional authentication algorithm hmac-sha-256-128
set security ipsec security-association <sa name> manual direction bidirectional authentication key ascii-text <PSK value>

set protocols bgp group <group name> type external
set protocols bgp group <group name> local-as <local AS number>
set protocols bgp group <group name> neighbor <neighbor 1 address> authentication-key <PSK value>
set protocols bgp group <group name> neighbor <neighbor 1 address> ipsec-sa <SA name>

set protocols ospf area 0.0.0.1 interface <interface name>.<logical unit> authentication md5 1 key <PSK value>
set protocols ospf area 0.0.0.1 interface <interface name>.<logical unit> interface-type p2p
set protocols ospf area 0.0.0.1 interface <interface name>.<logical unit> ipsec-sa <SA name>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57477r844106_chk'
  tag severity: 'medium'
  tag gid: 'V-254025'
  tag rid: 'SV-254025r844108_rule'
  tag stig_id: 'JUEX-RT-000530'
  tag gtitle: 'SRG-NET-000230-RTR-000001'
  tag fix_id: 'F-57428r844107_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
