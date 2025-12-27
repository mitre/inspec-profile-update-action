control 'SV-253994' do
  title 'The Juniper multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages from unauthorized multicast groups and sources.
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

[edit protocols pim]
rp {
    rp-register-policy <policy name>;
} 

If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the RP router to filter PIM register messages received from a multicast DR for any undesirable multicast groups or sources.

set policy-options policy-statement <name> term filter_groups from route-filter <multicast address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_groups from route-filter <additional multicast address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_groups then reject

set policy-options policy-statement <name> term filter_source from source-address-filter <source address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_source from source-address-filter <additional source address>/<mask> <match criterion>
set policy-options policy-statement <name> term filter_source then reject

set policy-options policy-statement <name> term accept_others then accept

set protocols pim rp rp-register-policy <policy name>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57446r844013_chk'
  tag severity: 'low'
  tag gid: 'V-253994'
  tag rid: 'SV-253994r844015_rule'
  tag stig_id: 'JUEX-RT-000220'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-57397r844014_fix'
  tag 'documentable'
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
