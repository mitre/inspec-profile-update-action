control 'SV-253995' do
  title 'The Juniper multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Router (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages.
[edit policy-options]
policy-statement <name> {
    term filter_groups {
        from {
            route-filter <multicast address>/<mask> orlonger;
            route-filter <multicast address>/<mask> exact;
            <additional groups to filter>
        }
        then reject;
    }
    term filter_sources {
        from {
            source-address-filter <source host address>/32 exact;
            source-address-filter <source subnet address>/<mask> orlonger;
            <additional source addresses to filter>
        }
        then reject;
    }
    term accept_others {
        then accept;
    }
}
[edit protocols]
pim {
    mode sparse;
    import <policy name>;
}

Note: Alternative is to verify all designated routers are filtering IGMP Membership Report (a.k.a., join) messages received from hosts.

If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block registration messages for any undesirable multicast groups and Bogon sources, this is a finding.'
  desc 'fix', 'RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block join messages for reserved and any undesirable multicast groups.

set policy-options policy-statement <name> term filter_groups from route-filter <multicast address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_groups from route-filter <additional multicast address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_groups then reject

set policy-options policy-statement <name> term filter_source from source-address-filter <source address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_source from source-address-filter <additional source address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_source then reject

set policy-options policy-statement <name> term accept_others then accept

set protocols pim import <policy name>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57447r844016_chk'
  tag severity: 'low'
  tag gid: 'V-253995'
  tag rid: 'SV-253995r844018_rule'
  tag stig_id: 'JUEX-RT-000230'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-57398r844017_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
