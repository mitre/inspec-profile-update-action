control 'SV-87773' do
  title 'The virtual edge gateways must be deployed with routing adjacencies established with two or more physical routers.'
  desc 'An edge gateway is deployed to allow north-south traffic to flow between the virtualized network and the physical network, including destinations outside of the data center or enclave boundaries. The gateway establishes routing adjacencies between the virtual routers and physical routers. The gateway can also filter the north-south traffic to enforce security policies for communication between the physical and virtual workloads. 

Implementing the edge gateway in either active/standby or equal-cost multipath (ECMP) mode ensures there is always a virtual router to forward north-south traffic, assuming there is always a routing adjacency with a router in the physical network infrastructure. Having an adjacency with only one physical router creates a single point of failure regardless of the number of links deployed, there would be no connectivity between the virtual and physical workloads if a node failure occurred. Hence, it is imperative that each edge gateway is deployed with connectivity to two physical routers.'
  desc 'check', 'Review the network topology diagram for both the physical infrastructure and the network virtualization platform (NVP) to determine if the virtual edge gateways have routing adjacencies with two or more physical routers. In addition, verify that the router adjacencies are established by having the administrator enter the appropriate commands that will show the neighbor relationship between the edge gateway and upstream routers. 

If the virtual edge gateway does not have routing adjacencies established with two or more physical routers, this is a finding.'
  desc 'fix', 'Configure the virtual edge gateways to have routing adjacencies established with two or more physical routers.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73255r1_chk'
  tag severity: 'low'
  tag gid: 'V-73121'
  tag rid: 'SV-87773r1_rule'
  tag stig_id: 'NET-SDN-029'
  tag gtitle: 'NET-SDN-029'
  tag fix_id: 'F-79567r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
