control 'SV-217089' do
  title 'The Juniper multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join only multicast groups that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to join only those groups that have been approved.

Verify that a group policy has been configured to filter IGMP join requests as shown in the example below.

protocols {
    igmp {
        interface ge-1/0/1.0 {
            group-policy MULTICAST_JOIN_POLICY;
        }
    }

Verify that the group policy only allows join requests for those groups that have been approved.

policy-options {
    …
    …
    …
    }
    policy-statement MULTICAST_JOIN_POLICY {
        …
        …
        …
        }
        term BAD_GROUPS {
            from {
                route-filter 224.1.1.0/24 orlonger;
                route-filter 225.1.2.3/32 exact;
                route-filter 239.0.0.0/8 orlonger;
                …
                …
                …
                route-filter 232.0.0.0/8 orlonger;
            }
            then reject;
        }
        term ALLOW_APPROVED {
            then accept;
        }
    }

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation. This requirement is not applicable to Any Source Multicast (ASM) since the filtering is being performed by the Rendezvous Point router.

If the DR is not filtering IGMP or MLD report messages to only allow joins for approved groups, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups that have been approved.

Configure a multicast join policy to filter groups that have not been approved as shown in the example below.

[edit policy-options policy-statement MULTICAST_JOIN_POLICY]
set term BAD_GROUPS from route-filter 224.1.1.0/24 orlonger
set term BAD_GROUPS from route-filter 225.1.2.3/32 exact
set term BAD_GROUPS from route-filter 239.0.0.0/8 orlonger
set term BAD_GROUPS then reject
set term ALLOW_APPROVED then accept

Apply the policy to all interfaces enabled for IGMP.

[edit protocols igmp]
set interface ge-1/0/1.0 group-policy MULTICAST_JOIN_POLICY'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18318r297135_chk'
  tag severity: 'low'
  tag gid: 'V-217089'
  tag rid: 'SV-217089r639663_rule'
  tag stig_id: 'JUNI-RT-000850'
  tag gtitle: 'SRG-NET-000364-RTR-000114'
  tag fix_id: 'F-18316r297136_fix'
  tag 'documentable'
  tag legacy: ['V-90961', 'SV-101171']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
