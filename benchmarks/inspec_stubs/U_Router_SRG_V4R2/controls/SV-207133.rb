control 'SV-207133' do
  title 'The router must be configured to restrict traffic destined to itself.'
  desc 'The route processor handles traffic destined to the router—the key component used to build forwarding paths and is also instrumental with all network management functions. Hence, any disruption or DoS attack to the route processor can result in mission critical network outages.'
  desc 'check', 'Review the access control list (ACL) or filter for the router receive path and verify that it will only process specific management plane and control plane traffic from specific sources.

If the router is not configured with a receive-path filter to restrict traffic destined to itself, this is a finding.

Note: If the platform does not support the receive path filter, verify that all Layer 3 interfaces have an ingress ACL to control what packets are allowed to be destined to the router for processing.'
  desc 'fix', 'Configure all routers with receive path filters to restrict traffic destined to the router.'
  impact 0.7
  ref 'DPMS Target Router'
  tag check_id: 'C-7394r382337_chk'
  tag severity: 'high'
  tag gid: 'V-207133'
  tag rid: 'SV-207133r604135_rule'
  tag stig_id: 'SRG-NET-000205-RTR-000001'
  tag gtitle: 'SRG-NET-000205'
  tag fix_id: 'F-7394r382338_fix'
  tag 'documentable'
  tag legacy: ['V-78215', 'SV-92921']
  tag cci: ['CCI-001097']
  tag nist: ['SC-7 a']
end
