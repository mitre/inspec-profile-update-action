control 'SV-95489' do
  title 'The SDN controller must be configured to only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or data center. Additionally, unrestricted traffic may transit a network consuming bandwidth and network node resources. Access control policies and access control lists implemented on routers and switches can control the flow of network traffic by ensuring that the flow of traffic is only allowed from authorized sources to authorized destinations. Furthermore, the SDN controller provides flow rules to the SDN-enabled routers and switches to populate their forwarding tables. SDN-enabled routers and switches will drop packets for flows that are not permitted by the controller. Also when reactive flow setup occurs (switch has no flow entry in the forwarding table for specific flow), the controller can respond to the switch to drop the packet or provide the device with a new flow entry. It is imperative that the SDN controller enforces perimeter security by deploying strict flow entries to the SDN-enabled edge routers.'
  desc 'check', 'Review the SDN configuration to determine if it enforces perimeter security by deploying strict flow entries to the SDN-enabled edge routers to only allow incoming traffic that is authorized. 

If the SDN controller is not configured to only allow incoming communications from organization-defined authorized sources routed to organization-defined authorized destinations, this is a finding.'
  desc 'fix', 'Configure the SDN controller to enforce perimeter security by deploying strict flow entries to the SDN-enabled edge routers to only allow incoming traffic that is authorized.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80515r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80779'
  tag rid: 'SV-95489r1_rule'
  tag stig_id: 'SRG-NET-000364-SDN-000730'
  tag gtitle: 'SRG-NET-000364'
  tag fix_id: 'F-87633r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002403']
  tag nist: ['SC-7 (11)']
end
