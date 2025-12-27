control 'SV-217085' do
  title 'The Juniper multicast Rendezvous Point (RP) router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'Review the router configuration to determine if forwarding cache thresholds are defined as shown in the example below.

routing-options {
    multicast {
        …
        …
        …
        }
        forwarding-cache {
            threshold {
                suppress 5000;
                reuse 4000;
            }
        }
    }
}

If the RP router is not configured to limit the multicast forwarding cache to ensure that its resources are not saturated, this is a finding.'
  desc 'fix', 'Configure the router to limit the multicast forwarding cache for source-active entries.

[edit routing-options multicast]
set forwarding-cache threshold suppress 5000 reuse 4000'
  impact 0.3
  ref 'DPMS Target Juniper Router RTR'
  tag check_id: 'C-18314r297123_chk'
  tag severity: 'low'
  tag gid: 'V-217085'
  tag rid: 'SV-217085r604135_rule'
  tag stig_id: 'JUNI-RT-000810'
  tag gtitle: 'SRG-NET-000362-RTR-000120'
  tag fix_id: 'F-18312r297124_fix'
  tag 'documentable'
  tag legacy: ['SV-101163', 'V-90953']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
