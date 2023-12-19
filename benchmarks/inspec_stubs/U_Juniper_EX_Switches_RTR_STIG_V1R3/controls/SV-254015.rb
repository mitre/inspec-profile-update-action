control 'SV-254015' do
  title 'The Juniper BGP router must be configured to reject outbound route advertisements for any prefixes belonging to the IP core.'
  desc 'Outbound route advertisements belonging to the core can result in traffic either looping or being black holed, or at a minimum, using a nonoptimized path.'
  desc 'check', 'Review the BGP router configuration to verify that there is a filter defined to block route advertisements for prefixes that belong to the IP core. 

Verify an appropriate prefix-list containing the IP core prefixes is referenced in a policy-statement. For example:
[edit policy-options]
prefix-list ip-core-ipv4 {
    192.0.2.0/24;
}
prefix-list ip-core-ipv6 {
    2001:db8:2::/64;
}
policy-statement advertise-bgp-prefix {
    term exclude-ipv4-core {
        from {
            prefix-list ip-core-ipv4;
        }
        then reject;
    }
    term exclude-ipv6-core {
        from {
            prefix-list ip-core-ipv6;
        }
        then reject;
    }
    term default {
        then accept;
    }
}

The prefix filter must be referenced outbound on the appropriate BGP neighbor statements. For example:
[edit protocols]
bgp {
    group eBGP {
        type external;
        export advertise-bgp-prefix;
        neighbor 192.0.2.11 {
            export advertise-bgp-prefix;
        }
    }
    export advertise-bgp-prefix;
}

Note: Juniper routers support global, group, and neighbor export statements with the more specific definition taking precedence. Ensure more specific export policies (e.g., neighbor and group) do not reverse higher level export statements.

If the router is not configured to reject outbound route advertisements that belong to the IP core, this is a finding.'
  desc 'fix', 'Configure all eBGP routers to filter outbound route advertisements belonging to the IP core.

For example:
set policy-options prefix-list ip-core-ipv4 192.0.2.0/24
set policy-options prefix-list ip-core-ipv6 2001:db8:2::/64
set policy-options policy-statement advertise-bgp-prefix term exclude-ipv4-core from prefix-list ip-core-ipv4
set policy-options policy-statement advertise-bgp-prefix term exclude-ipv4-core then reject
set policy-options policy-statement advertise-bgp-prefix term exclude-ipv6-core from prefix-list ip-core-ipv6
set policy-options policy-statement advertise-bgp-prefix term exclude-ipv6-core then reject
set policy-options policy-statement advertise-bgp-prefix term default then accept

set protocols bgp group eBGP type external
set protocols bgp group eBGP export advertise-bgp-prefix
set protocols bgp group eBGP neighbor 192.0.2.11 export advertise-bgp-prefix
set protocols bgp export advertise-bgp-prefix'
  impact 0.5
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57467r844076_chk'
  tag severity: 'medium'
  tag gid: 'V-254015'
  tag rid: 'SV-254015r844078_rule'
  tag stig_id: 'JUEX-RT-000430'
  tag gtitle: 'SRG-NET-000205-RTR-000006'
  tag fix_id: 'F-57418r844077_fix'
  tag 'documentable'
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
