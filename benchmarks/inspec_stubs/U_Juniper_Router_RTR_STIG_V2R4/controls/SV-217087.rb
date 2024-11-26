control 'SV-217087' do
  title 'The Juniper multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Join messages received from the Designated Juniper router (DR) for any undesirable multicast groups.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that join messages are only accepted for authorized multicast groups and sources.'
  desc 'check', 'Review the RP router configuration to determine if it filters PIM join messages for any reserved multicast groups.

Step 1: Verify that a PIM import statement has been configured as shown in the example below:

protocols {
    …
    …
    …
    }
    pim {
           import MULTICAST_JOIN_POLICY;

Step 2: Verify that the join policy has defined both bad multicast groups and sources as shown in the example below:

policy-options {
    …
    …
    …
    }
    policy-statement MULTICAST_JOIN_POLICY {
        term BAD_GROUPS {
            from {
                route-filter 224.1.1.0/24 orlonger;
                route-filter 225.1.2.3/32 exact;
                …
                …
                …
                route-filter 232.0.0.0/8 orlonger;
            }
            then reject;
        }
        term ALLOW_OTHER {
            then accept;
        }
    }
If the RP router peering with PIM-SM routers is not configured with a PIM import policy to block join messages for any undesirable multicast groups, this is a finding.'
  desc 'fix', 'RP routers that are peering with customer PIM-SM routers must implement a PIM import policy to block join messages for any undesirable multicast groups.

Step 1: Configure a multicast join policy to filter bad groups and sources as shown in the example below:

[edit policy-options policy-statement MULTICAST_JOIN_POLICY]
set term BAD_GROUPS from route-filter 224.1.1.0/24 orlonger
set term BAD_GROUPS from route-filter 225.1.2.3/32 exact
…
…
…
set term BAD_GROUPS then reject
set term ALLOW_OTHER then accept

Step 2: Configure PIM to enable the join policy as shown in the example below:

[edit protocols pim]
set import MULTICAST_JOIN_POLICY'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18316r297129_chk'
  tag severity: 'low'
  tag gid: 'V-217087'
  tag rid: 'SV-217087r604135_rule'
  tag stig_id: 'JUNI-RT-000830'
  tag gtitle: 'SRG-NET-000019-RTR-000014'
  tag fix_id: 'F-18314r297130_fix'
  tag 'documentable'
  tag legacy: ['SV-101167', 'V-90957']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
