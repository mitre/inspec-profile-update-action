control 'SV-80617' do
  title 'The HP FlexFabric Switch must protect against or limit the effects of denial of service (DoS) attacks by employing control plane protection.'
  desc 'The Route Processor (RP) is critical to all network operations because it is the component used to build all forwarding paths for the data plane via control plane processes. It is also instrumental with ongoing network management functions that keep the routers and links available for providing network services. Any disruption to the Route Processor or the control and management planes can result in mission-critical network outages. 

A DoS attack targeting the Route Processor can result in excessive CPU and memory utilization. To maintain network stability and Route Processor security, the router must be able to handle specific control plane and management plane traffic that is destined to the Route Processor. In the past, one method of filtering was to use ingress filters on forwarding interfaces to filter both forwarding path and receiving path traffic. However, this method does not scale well as the number of interfaces grows and the size of the ingress filters grow. Control plane policing increases the security of routers and multilayer switches by protecting the Route Processor from unnecessary or malicious traffic. Filtering and rate limiting the traffic flow of control plane packets can be implemented to protect routers against reconnaissance and DoS attacks, allowing the control plane to maintain packet forwarding and protocol states despite an attack or heavy load on the router or multilayer switch.'
  desc 'check', 'Verify that there is a control plane policy configured on the HP FlexFabric to rate limit control plane traffic using the following command: display qos policy control-plane slot 1. If the HP FlexFabric Switch is not configured to rate limit control plane traffic, this is a finding.'
  desc 'fix', '1. Classify control plane traffic
traffic classifier Class-Control-Plane operator or  if-match control-plane protocol ospf bgp

2. Create policer to rate limit the control plane traffic 
traffic behavior Police-Control-Plane  car cir nnn cbs nnnn ebs 0 green pass red discard yellow pass

3. Create QoS policy using the traffic classifier and traffic behavior 
qos policy Policy-Control-Plane  classifier Class-Control-Plane behavior Police-Control-Plane

4. Apply the QoS policy to rate limit control-plane traffic
control-plane slot 1  qos apply policy Policy-Control-Plane inbound'
  impact 0.5
  ref 'DPMS Target HP Flex Fabric Switch 7 RTR'
  tag check_id: 'C-66773r1_chk'
  tag severity: 'medium'
  tag gid: 'V-66127'
  tag rid: 'SV-80617r1_rule'
  tag stig_id: 'HFFS-RT-000020'
  tag gtitle: 'SRG-NET-000362-RTR-000110'
  tag fix_id: 'F-72203r1_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
