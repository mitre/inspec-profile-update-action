control 'SV-95483' do
  title 'The SDN controller must be configured to enforce a policy to manage bandwidth and to limit the effects of a packet-flooding Denial of Service (DoS) attack.'
  desc %q(A network element experiencing a DoS attack will not be able to handle production traffic load. The high utilization and CPU caused by a DoS attack will also have an effect on control keep-alives and timers used for neighbor peering resulting in route flapping and will eventually black hole production traffic. 

The device must be configured to contain and limit a DoS attack's effect on the device's resource utilization. The use of redundant components and load balancing are examples of mitigating "flood type" DoS attacks through increased capacity.)
  desc 'check', 'Review the SDN controller configuration to verify that it is configured to enforce a policy to manage bandwidth and to limit the effects of a packet-flooding DoS attack. The implementation could be driven by a service application via the northbound API that contains the policy.

If the SDN controller is not configured to enforce a policy to manage bandwidth and limit the effect of a packet-flooding DoS attack, this is a finding.'
  desc 'fix', 'Configure the SDN controller to enforce a policy to manage bandwidth and to limit the effects of a packet-flooding Denial of Service (DoS) attack. This can be implemented via northbound API from a service application containing the policy.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80509r2_chk'
  tag severity: 'medium'
  tag gid: 'V-80773'
  tag rid: 'SV-95483r1_rule'
  tag stig_id: 'SRG-NET-000193-SDN-000285'
  tag gtitle: 'SRG-NET-000193'
  tag fix_id: 'F-87627r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001095']
  tag nist: ['SC-5 (2)']
end
