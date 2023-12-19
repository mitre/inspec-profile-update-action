control 'SV-217090' do
  title 'The Juniper multicast Designated Router (DR) must be configured to filter the Internet Group Management Protocol (IGMP) and Multicast Listener Discovery (MLD) Report messages to allow hosts to join a multicast group only from sources that have been approved by the organization.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. Large unicast flows tend to be fairly isolated (i.e., someone doing a file download here or there), whereas multicast can have broader impact on bandwidth consumption, resulting in extreme network congestion. Hence, it is imperative that there is multicast admission control to restrict which multicast groups hosts are allowed to join via IGMP or MLD.'
  desc 'check', 'Review the configuration of the DR to verify that it is filtering IGMP or MLD report messages, allowing hosts to only join multicast groups from sources that have been approved.

Verify that a group policy has been configured to filter IGMP join requests as shown in the example below.

protocols {
    igmp {
        interface ge-1/0/1.0 {
            group-policy MULTICAST_JOIN_POLICY;
        }
    }

Verify that the policy only allows join requests for those sources that have been approved.

policy-options {
    …
    …
    …
    }
    policy-statement MULTICAST_JOIN_POLICY {
        term BAD_SOURCES {
            from {
                source-address-filter x.x.x.x/32 exact;
                source-address-filter x.x.x.x/24 orlonger;
            }
            then reject;
        }
        …
        …
        …
        }
        term ALLOW_APPROVED {
            then accept;
        }
    }

Note: This requirement is only applicable to Source Specific Multicast (SSM) implementation.

If the DR is not filtering IGMP or MLD report messages to only allow joins for approved sources, this is a finding.'
  desc 'fix', 'Configure the DR to filter the IGMP and MLD report messages to allow hosts to join only those multicast groups from sources that have been approved.

Configure a multicast join policy to filter unauthorized multicast sources.

[edit policy-options policy-statement MULTICAST_JOIN_POLICY]
set term BAD_SOURCES from source-address-filter x.x.x.x/32 exact
set term BAD_SOURCES from source-address-filter x.x.x.x/24 orlonger
set term BAD_SOURCES then reject
set term ALLOW_APPROVED then accept

 Apply the policy to all interfaces enabled for IGMP.

[edit protocols igmp]
set interface ge-1/0/1.0 group-policy MULTICAST_JOIN_POLICY'
  impact 0.5
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18319r297138_chk'
  tag severity: 'medium'
  tag gid: 'V-217090'
  tag rid: 'SV-217090r604135_rule'
  tag stig_id: 'JUNI-RT-000860'
  tag gtitle: 'SRG-NET-000364-RTR-000115'
  tag fix_id: 'F-18317r297139_fix'
  tag 'documentable'
  tag legacy: ['SV-101173', 'V-90963']
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
