control 'SV-207159' do
  title 'The multicast Rendezvous Point (RP) router must be configured to limit the multicast forwarding cache so that its resources are not saturated by managing an overwhelming number of Protocol Independent Multicast (PIM) and Multicast Source Discovery Protocol (MSDP) source-active entries.'
  desc 'MSDP peering between networks enables sharing of multicast source information. Enclaves with an existing multicast topology using PIM-SM can configure their RP routers to peer with MSDP routers. As a first step of defense against a denial-of-service (DoS) attack, all RP routers must limit the multicast forwarding cache to ensure that router resources are not saturated managing an overwhelming number of PIM and MSDP source-active entries.'
  desc 'check', 'Review the router configuration to determine if forwarding cache thresholds are defined.

If the RP router is not configured to limit the multicast forwarding cache to ensure that its resources are not saturated, this is a finding.'
  desc 'fix', 'Configure MSDP-enabled RP routers to limit the multicast forwarding cache for source-active entries.'
  impact 0.3
  ref 'DPMS Target Router'
  tag check_id: 'C-7420r382505_chk'
  tag severity: 'low'
  tag gid: 'V-207159'
  tag rid: 'SV-207159r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000120'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7420r382506_fix'
  tag 'documentable'
  tag legacy: ['SV-93033', 'V-78327']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
