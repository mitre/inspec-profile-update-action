control 'SV-87743' do
  title 'Physical SDN controllers and servers hosting SDN applications must reside within the management network with multiple paths that are secured by a firewall to inspect all ingress traffic.'
  desc 'Management and orchestration systems deploy and configure network devices such as switches and routers, both physical and virtual. SDN controllers are made aware of the deployments and are able to define the network topology through abstraction. The controllers are then able to provide forwarding table information to each router or switch instance within the SDN infrastructure. 

If an SDN-aware router or switch received erroneous forwarding information from a rogue controller, traffic could be black-holed or even forwarded to a malicious user to sniff traffic and to perform a man-in-the-middle attack.

If attackers could leverage a vulnerable northbound API, they would have control over the SDN infrastructure through the controller by creating their own polices. If the SDN controller were to receive fictitious information from a rogue application, non-optimized network paths would be produced that could disrupt network operations, resulting in inefficient application and business processes.

If either the orchestration or management system were breached, invalid network service requests could be processed that could exhaust compute, storage, and network resources, leaving no resources available for legitimate business requirements.'
  desc 'check', 'Review the SDN infrastructure topology to verify that the all physical SDN controllers, management appliances, and servers hosting SDN applications reside within the management network that has multiple paths and is also secured by a firewall. 

If these physical NVP components do not reside within the management network with multiple paths, and are not secured by a firewall, this is a finding. 

Note: If the SDN physical components reside within an out-of-band network, this requirement would not be applicable.'
  desc 'fix', 'Deploy all physical controllers, management appliances, and servers hosting SDN applications into the management network with multiple paths that are secured by a firewall inspecting all ingress traffic.'
  impact 0.5
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73225r1_chk'
  tag severity: 'medium'
  tag gid: 'V-73091'
  tag rid: 'SV-87743r1_rule'
  tag stig_id: 'NET-SDN-010'
  tag gtitle: 'NET-SDN-010'
  tag fix_id: 'F-79537r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
