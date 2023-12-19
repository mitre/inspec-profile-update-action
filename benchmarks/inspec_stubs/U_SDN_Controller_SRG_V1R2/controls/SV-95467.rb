control 'SV-95467' do
  title 'The SDN controller must be configured to enforce approved authorizations for controlling the flow of traffic within the network based on organization-defined information flow control policies.'
  desc 'Unrestricted traffic may contain malicious traffic which poses a threat to an enclave or data center. Additionally, unrestricted traffic may transit a network consuming bandwidth and network node resources. Access control policies and access control lists implemented on routers and switches can control the flow of network traffic by ensuring that the flow of traffic is only allowed from authorized sources to authorized destinations. Furthermore, the SDN controller provides flow rules to the SDN-enabled routers and switches to populate their forwarding tables. SDN-enabled routers and switches will drop packets for flows that are not permitted by the controller. Also when reactive flow setup occurs (switch has no flow entry in the forwarding table for specific flow), the controller can respond to the switch to drop the packet or provide the device with a new flow entry. It is imperative that both proactive and reactive flow setup must be implemented based on organization-defined information flow control policies.'
  desc 'check', 'Review the SDN controller configuration to determine if it creates and distributes forwarding table flow entries based on organization-defined information flow control policies. The implementation could be driven by a service application via the northbound API that contains the flow control policy and forwarding rules. 

If the SDN controller is not configured to enforce approved authorizations for controlling the flow of traffic within the network based on organization-defined information flow control policies, this is a finding.'
  desc 'fix', 'Configure the SDN controller to create and distribute forwarding table flow entries based on organization-defined information flow control policies. The implementation could be driven by a service application via the northbound API that contains the flow control policy and forwarding rules.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80493r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80757'
  tag rid: 'SV-95467r1_rule'
  tag stig_id: 'SRG-NET-000018-SDN-000015'
  tag gtitle: 'SRG-NET-000018'
  tag fix_id: 'F-87611r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001368']
  tag nist: ['AC-4']
end
