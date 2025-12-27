control 'SV-254027' do
  title 'The Juniper router must be configured to use keys with a duration not exceeding 180 days for authenticating routing protocol messages.'
  desc 'If the keys used for routing protocol authentication are guessed, the malicious user could create havoc within the network by advertising incorrect routes and redirecting traffic. Some routing protocols allow the use of key chains for authentication. A key chain is a set of keys that is used in succession, with each having a lifetime of no more than 180 days. Changing the keys frequently reduces the risk of them eventually being guessed.

Keys cannot be used during time periods for which they are not activated. If a time period occurs during which no key is activated, neighbor authentication cannot occur, and therefore routing updates will fail. Therefore, ensure that for a given key chain, key activation times overlap to avoid any period of time during which no key is activated.'
  desc 'check', 'This requirement is not applicable for the DODIN Backbone.

For each authenticated routing protocol session, review the configured key expiration dates.
[edit security]
authentication-key-chains {
    key-chain <name> {
        key 1 {
            secret "$9$vNbM7Vg4ZjkPJGn/AtOB7-d"; ## SECRET-DATA
            start-time "2021-1-1.00:00:00 -0700";
            algorithm md5;
        }
        key 2 {
            secret "$9$MAQL7VgoGqmTwYmTz3tpWLxNwY4aZjk."; ## SECRET-DATA
            start-time "2021-5-31.00:00:00 -0700";
            algorithm md5;
        }
    }
}
[edit protocols]
bgp {
    group eBGP {
        authentication-key-chain <name>;
        neighbor 1.2.3.4 {
            authentication-key-chain <name>;
        }
    }
    authentication-key-chain <name>;
}

Note: BGP supports authentication globally, at the group level, and individually for each neighbor. The most specific authentication configuration is applied.
ospf {
    area 0.0.0.2 {
        interface ge-0/0/0.0 {
            authentication {
                md5 0 key "$9$vG08xd24Zk.5bs.5QFAtM8X7bsgoJDHq" start-time "2021-1-1.00:00:00 -0700"; ## SECRET-DATA
                md5 1 key "$9$m5z6p0IreW9AeWLxwsP5QF9AuO1hyl" start-time "2021-5-31.00:00:00 -0700"; ## SECRET-DATA
            }
        }
    }                                   
}

If any key has a lifetime of more than 180 days, this is a finding.'
  desc 'fix', 'This requirement is not applicable for the DODIN Backbone.

For each authenticated routing protocol session, configure each key to have a lifetime of no more than 180 days.

set security authentication-key-chains key-chain <name> key <number-1> secret <key value>
set security authentication-key-chains key-chain <name> key <number-1> start-time <YYYY-MM-DD.HH:MM>
set security authentication-key-chains key-chain <name> key <number-1> algorithm md5
set security authentication-key-chains key-chain <name> key <number-2> secret <key value>
set security authentication-key-chains key-chain <name> key <number-2> start-time <YYYY-MM-DD.HH:MM>
set security authentication-key-chains key-chain <name> key <number-2> algorithm md5

set protocols bgp group <name> authentication-key-chain <name>
set protocols bgp group <name> neighbor <neighbor address> authentication-key-chain <name>
set protocols bgp authentication-key-chain <name>

set protocols ospf area <area number> interface <interface name>.<logical unit> authentication md5 <number> key <key value>
set protocols ospf area <area number> interface <interface name>.<logical unit> authentication md5 <number> start-time <YYYY-MM-DD.HH:MM>
set protocols ospf area <area number> interface <interface name>.<logical unit> authentication md5 <number> key <key value>
set protocols ospf area <area number> interface <interface name>.<logical unit> authentication md5 <number> start-time <YYYY-MM-DD.HH:MM>'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57479r844112_chk'
  tag severity: 'medium'
  tag gid: 'V-254027'
  tag rid: 'SV-254027r844114_rule'
  tag stig_id: 'JUEX-RT-000550'
  tag gtitle: 'SRG-NET-000230-RTR-000003'
  tag fix_id: 'F-57430r844113_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002205']
  tag nist: ['CM-6 b', 'AC-4 (17)']
end
