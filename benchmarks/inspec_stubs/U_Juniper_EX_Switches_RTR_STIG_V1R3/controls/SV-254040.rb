control 'SV-254040' do
  title 'The Juniper multicast RP router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'Review the router configuration to determine if forwarding cache thresholds are defined.

[edit routing-options]
multicast {
    forwarding-cache {
        threshold {
            suppress <1..200000>;
            reuse <1..200000>;
            log-warning <percent to generate warning>;
        }
    }
}

If the RP router is not configured to limit the multicast forwarding cache to ensure that its resources are not saturated, this is a finding.'
  desc 'fix', 'Configure MSDP-enabled RP routers to limit the multicast forwarding cache for source-active entries.

set routing-options multicast forwarding-cache threshold suppress <1..200000>
set routing-options multicast forwarding-cache threshold reuse <1..200000>
set routing-options multicast forwarding-cache threshold log-warning <percent to generate warning>'
  impact 0.3
  ref 'DPMS Target Juniper EX Series Switches Router'
  tag check_id: 'C-57492r844151_chk'
  tag severity: 'low'
  tag gid: 'V-254040'
  tag rid: 'SV-254040r844261_rule'
  tag stig_id: 'JUEX-RT-000680'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-57443r844152_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
