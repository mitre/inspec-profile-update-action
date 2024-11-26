control 'SV-254062' do
  title 'The Juniper MPLS router must be configured to synchronize IGP and LDP to minimize packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.'
  desc 'Packet loss can occur when an IGP adjacency is established and the router begins forwarding packets using the new adjacency before the LDP label exchange completes between the peers on that link. Packet loss can also occur if an LDP session closes and the router continues to forward traffic using the link associated with the LDP peer rather than an alternate pathway with a fully synchronized LDP session. The MPLS LDP-IGP Synchronization feature provides a means to synchronize LDP with OSPF or IS-IS to minimize MPLS packet loss. When an IGP adjacency is established on a link but LDP-IGP synchronization is not yet achieved or is lost, the IGP will advertise the max-metric on that link.'
  desc 'check', 'Review the router OSPF or IS-IS configuration.

Verify that LDP will synchronize with the link-state routing protocol.
[edit protocols]
ospf {
    area <number> {
        interface <name>.<logical unit> {
            authentication {
                md5 <key number> key "$8$aes256-gcm$hmac-sha2-256$100$LfJ7NdAYx/0$+4wGg1QJKLzkaAmVCGxBUQ$n0XxNofUtXE8aoJBhFNDDQ$uIDW/H+VY6U"; ## SECRET-DATA
            }
            ldp-synchronization {
                hold-time 10;
            }
        }
        interface <name>.<logical unit> {
            ipsec-sa <name>;
            ldp-synchronization {
                hold-time 10;
            }
        }
    }
}
ldp {
    interface <name>.<logical unit>;
}
-OR-
isis {
    interface <name>.<logical unit> {
        ldp-synchronization {
            hold-time 10;
        }
    }
    level 1 authentication-key-chain <name>;
    level 2 authentication-key-chain <name>;
}
mpls {
    interface <name>.<logical unit>;
}

If the router is not configured to synchronize IGP and LDP, this is a finding.'
  desc 'fix', 'Configure the MPLS router to synchronize IGP and LDP, minimizing packet loss when an IGP adjacency is established prior to LDP peers completing label exchange.

set protocols ospf area <number> interface <name>.<logical unit> authentication md5 <key number> <PSK>
set protocols ospf area <number> interface <name>.<logical unit> ldp-synchronize hold-time 10
set protocols ldp interface <name>.<logical unit>

-OR-

set protocols isis level 1 authentication-key-chain <name>
set protocols isis level 2 authentication-key-chain <name>
set protocols isis interface <name>.<logical unit> ldp-synchronize hold-time 10
set protocols mpls interface <name>.<logical unit>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57514r844217_chk'
  tag severity: 'low'
  tag gid: 'V-254062'
  tag rid: 'SV-254062r844219_rule'
  tag stig_id: 'JUEX-RT-000900'
  tag gtitle: 'SRG-NET-000512-RTR-000003'
  tag fix_id: 'F-57465r844218_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
