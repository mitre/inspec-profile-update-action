control 'SV-254050' do
  title 'The Juniper multicast Designated Router (DR) must be configured to filter the IGMP and MLD Report messages to allow hosts to join only multicast groups that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone downloading a file here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to join only those groups that have been approved.

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. This requirement is not applicable to Any Source Multicast (ASM) since the filtering is being performed by the Rendezvous Point router.

[edit policy-options]
policy-statement <name> {
    term unauth-groups {
        from {
            route-filter 224.0.1.2/32 exact;
            route-filter 224.0.2.2/32 exact;
        }
        then reject;
    }
    term allow-others {
        then accept;
    }
}
policy-statement <name IPv6> {
    term unauth-groups {
        from {
            route-filter fec0:1:1:4::/64 exact;
        }
        then reject;
    }
    term allow-others {
        then accept;
    }
}

[edit protocols]
igmp {
    interface <name>.<logical unit> {
        group-policy <policy name>;
    }
}
mld {
    interface <name>.<logical unit> {
        group-policy <policy name IPv6>;
    }
}

If the DR is not filtering IGMP or MLD report messages, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups that have been approved.

set policy-options policy-statement <name> term unauth-groups from route-filter 224.0.1.2/32 exact
set policy-options policy-statement <name> term unauth-groups from route-filter 224.0.2.2/32 exact
set policy-options policy-statement <name> term unauth-groups then reject
set policy-options policy-statement <name> term accept-others then accept

set policy-options policy-statement <name IPv6> term unauth-groups from route-filter fec0:1:1:4::/64 exact
set policy-options policy-statement <name IPv6> term unauth-groups then reject
set policy-options policy-statement <name IPv6> term accept-others then accept

set protocols igmp interface <name>.<logical unit> group-policy <policy name>
set protocols mld interface <name>.<logical unit> group-policy <policy name IPv6>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57502r844181_chk'
  tag severity: 'low'
  tag gid: 'V-254050'
  tag rid: 'SV-254050r844262_rule'
  tag stig_id: 'JUEX-RT-000780'
  tag gtitle: 'SRG-NET-000364-RTR-000114'
  tag fix_id: 'F-57453r844182_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
