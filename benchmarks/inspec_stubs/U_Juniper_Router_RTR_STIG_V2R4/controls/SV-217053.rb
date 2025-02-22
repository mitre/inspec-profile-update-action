control 'SV-217053' do
  title 'The Juniper BGP router must be configured to reject inbound route advertisements for any Bogon prefixes.'
  desc 'Accepting route advertisements for Bogon prefixes can result in the local autonomous system (AS) becoming a transit for malicious traffic as it will in turn advertise these prefixes to neighbor autonomous systems.'
  desc 'check', 'Review the router configuration to verify that it will reject BGP routes for any Bogon prefixes.

Verify a prefix list has been configured containing the current Bogon prefixes as shown in the example below.

policy-options {
    prefix-list BOGON_PREFIXES {
        0.0.0.0/8;
        10.0.0.0/8;
        100.64.0.0/10;
        127.0.0.0/8;
        169.254.0.0/16;
        172.16.0.0/12;
        192.0.0.0/24;
        192.0.2.0/24;
        192.168.0.0/16;
        198.18.0.0/15;
        198.51.100.0/24;
        203.0.113.0/24;
        224.0.0.0/4;
        240.0.0.0/4;
    }
}

Verify that a policy has been configured to reject the Bogon prefixes.

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
        term ACCEPT_OTHERS {
            then accept;
        }
    }
}

Verify that the configured policy to filter Bogons has been applied to external BGP peers as shown in the example below.

protocols {
    bgp {
        group GROUP_AS4 {
            type external;
            import FILTER_ROUTES;
            peer-as 4;
            neighbor x.x.x.x;
        }
    }

If the router is not configured to reject inbound route advertisements for any Bogon prefixes, this is a finding.'
  desc 'fix', 'Configure the router to reject inbound route advertisements for any Bogon prefixes.

Configure a prefix list containing the current Bogon prefixes as shown below.

[edit policy-options]
set prefix-list BOGON_PREFIXES 0.0.0.0/8
set prefix-list BOGON_PREFIXES 10.0.0.0/8
set prefix-list BOGON_PREFIXES 100.64.0.0/10
set prefix-list BOGON_PREFIXES 127.0.0.0/8
set prefix-list BOGON_PREFIXES 169.254.0.0/16
set prefix-list BOGON_PREFIXES 172.16.0.0/12
set prefix-list BOGON_PREFIXES 192.0.0.0/24
set prefix-list BOGON_PREFIXES 192.0.2.0/24
set prefix-list BOGON_PREFIXES 192.168.0.0/16
set prefix-list BOGON_PREFIXES 198.18.0.0/15
set prefix-list BOGON_PREFIXES 198.51.100.0/24
set prefix-list BOGON_PREFIXES 203.0.113.0/24
set prefix-list BOGON_PREFIXES 224.0.0.0/4
set prefix-list BOGON_PREFIXES 240.0.0.0/4

Configure a policy-statement to reject Bogon prefixes.

set policy-statement FILTER_ROUTES term REJECT_BOGONS from prefix-list BOGON_PREFIXES
set policy-statement FILTER_ROUTES term REJECT_BOGONS then reject
set policy-statement FILTER_ROUTES term ACCEPT_OTHER then accept

Configure an import statement referencing the policy to reject Bogons on all external BGP peers.

[edit protocols bgp group GROUP_AS4]
set import FILTER_ROUTES'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18282r297027_chk'
  tag severity: 'medium'
  tag gid: 'V-217053'
  tag rid: 'SV-217053r604135_rule'
  tag stig_id: 'JUNI-RT-000480'
  tag gtitle: 'SRG-NET-000018-RTR-000002'
  tag fix_id: 'F-18280r297028_fix'
  tag 'documentable'
  tag legacy: ['SV-101101', 'V-90891']
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
