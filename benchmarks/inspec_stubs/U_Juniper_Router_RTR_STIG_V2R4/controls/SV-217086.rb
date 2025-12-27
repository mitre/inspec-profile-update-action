control 'SV-217086' do
  title 'The Juniper multicast Rendezvous Point (RP) router must be configured to filter Protocol Independent Multicast (PIM) Register messages received from the Designated Router (DR) for any undesirable multicast groups and sources.'
  desc 'Real-time multicast traffic can entail multiple large flows of data. An attacker can flood a network segment with multicast packets, over-using the available bandwidth and thereby creating a denial-of-service (DoS) condition. Hence, it is imperative that register messages are accepted only for authorized multicast groups and sources.'
  desc 'check', 'Verify that the RP router is configured to filter PIM register messages.

Verify that the RP has a register policy enabled as shown in the example below.

protocols {
    …
    …
    …
    }
    pim {
        rp {
            rp-register-policy MULTICAST_REGISTER_POLICY;
            local {
                address 2.2.2.2;
            }
        }

Verify that the register policy has defined both bad multicast groups and sources as shown in the example below.

policy-options {
    …
    …
    …
    }
    policy-statement MULTICAST_REGISTER_POLICY {
        term BAD_SOURCES {
            from {
                source-address-filter x.x.x.x/32 exact;
                source-address-filter x.x.x.x/24 orlonger;
            }
            then reject;
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
        term ALLOW_OTHER {
            then accept;
        }
    }

If the RP router peering with PIM-SM routers is not configured with a policy to block registration messages for any undesirable multicast groups and sources, this is a finding.'
  desc 'fix', 'Configure the router to filter PIM register messages received from a multicast DR for any undesirable multicast groups and sources.

[edit policy-options policy-statement MULTICAST_REGISTER_POLICY]
set term BAD_SOURCES from source-address-filter x.x.x.x/32 exact
set term BAD_SOURCES from source-address-filter x.x.x.x/24 orlonger
set term BAD_GROUPS from route-filter 224.1.1.0/24 orlonger
set term BAD_GROUPS from route-filter 225.1.2.3/32 exact
set term BAD_GROUPS from route-filter 239.0.0.0/8 orlonger
set term BAD_GROUPS then reject
set term ALLOW_OTHER then accept

[edit protocols pim rp]
set rp-register-policy MULTICAST_REGISTER_POLICY'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18315r297126_chk'
  tag severity: 'low'
  tag gid: 'V-217086'
  tag rid: 'SV-217086r604135_rule'
  tag stig_id: 'JUNI-RT-000820'
  tag gtitle: 'SRG-NET-000019-RTR-000013'
  tag fix_id: 'F-18313r297127_fix'
  tag 'documentable'
  tag legacy: ['SV-101165', 'V-90955']
  tag cci: ['CCI-001414']
  tag nist: ['AC-4']
end
