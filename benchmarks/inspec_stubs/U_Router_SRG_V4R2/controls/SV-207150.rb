control 'SV-207150' do
  title 'The router must be configured to protect against or limit the effects of denial-of-service (DoS) attacks by employing control plane protection.'
  desc 'The Route Processor (RP) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the RP or the control and management planes can result in mission-critical network outages.

A DoS attack targeting the RP can result in excessive CPU and memory utilization. To maintain network stability and RP security, the router must be able to handle specific control plane and management plane traffic that is destined to the RP. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grows. Control plane policing increases the security of routers and multilayer switches by protecting the RP from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Determine whether control plane protection has been implemented on the device by verifying traffic types have been classified based on importance levels and a policy has been configured to filter and rate limit the traffic according to each class.

If the router does not have control plane protection implemented, this is a finding.'
  desc 'fix', 'Implement control plane protection by classifying traffic types based on importance and configure filters to restrict and rate limit the traffic directed to and processed by the RP according to each class.'
  impact 0.5
  ref 'DPMS Target Router'
  tag check_id: 'C-7411r382433_chk'
  tag severity: 'medium'
  tag gid: 'V-207150'
  tag rid: 'SV-207150r604135_rule'
  tag stig_id: 'SRG-NET-000362-RTR-000110'
  tag gtitle: 'SRG-NET-000362'
  tag fix_id: 'F-7411r382434_fix'
  tag 'documentable'
  tag legacy: ['V-55781', 'SV-70035']
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
