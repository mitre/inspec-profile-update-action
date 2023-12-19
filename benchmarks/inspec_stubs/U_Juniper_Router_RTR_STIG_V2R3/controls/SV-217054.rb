control 'SV-217054' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements for any prefixes belonging to the local autonomous system (AS).'
  desc 'Accepting route advertisements belonging to the local AS can result in traffic looping or being black holed, or at a minimum using a non-optimized path.'
  desc 'check', 'Review the router configuration to verify that it will reject routes belonging to the local AS.

Verify a prefix list has been configured containing prefixes belonging to the local autonomous system as shown in the example below.

policy-options {
    …
    …
    …
    prefix-list OUR_PREFIXES {
        x.x.x.x/16;
    }

Verify that a policy has been configured to reject the local prefixes.

policy-options {
    …
    …
    …
    policy-statement FILTER_ROUTES {
        term REJECT_BOGONS {
            from {
                prefix-list BOGON_PREFIXES;
            }
            then reject;
        }
        term REJECT_OUR_PREFIXES {
            from {
                prefix-list OUR_PREFIXES;
            }
            then reject;
        }
        term ACCEPT_OTHER {
            then accept;
        }
    }
}

Verify that the configured policy to filter local prefixes has been applied to external BGP peers as shown in the example below.

protocols {
    bgp {
        group GROUP_AS4 {
            type external;
            import FILTER_ROUTES;
            peer-as 4;
            neighbor x.x.x.x;
        }
    }

If the router is not configured to reject inbound route advertisements belonging to the local AS, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements for any prefixes belonging to the local AS.

Configure a prefix list containing prefixes belonging to the local autonomous system.

[edit policy-options]
set prefix-list OUR_PREFIXES x.x.x.x/16

Configure a policy-statement to reject prefixes belonging to the local autonomous system. This can be done by adding a term to the existing policy to filter Bogons as shown in the example below.

[edit policy-options policy-statement FILTER_ROUTES]
set term REJECT_OUR_PREFIXES from prefix-list OUR_PREFIXES
set term REJECT_OUR_PREFIXES then reject
insert term REJECT_OUR_PREFIXES before term ACCEPT_OTHER

Note: There is no need change the BGP configuration assuming the import statement is already configured for all external neighbors.'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18283r297030_chk'
  tag severity: 'medium'
  tag gid: 'V-217054'
  tag rid: 'SV-217054r604135_rule'
  tag stig_id: 'JUNI-RT-000490'
  tag gtitle: 'SRG-NET-000018-RTR-000003'
  tag fix_id: 'F-18281r297031_fix'
  tag 'documentable'
  tag legacy: ['SV-101103', 'V-90893']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
