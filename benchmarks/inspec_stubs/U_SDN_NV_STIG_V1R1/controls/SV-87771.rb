control 'SV-87771' do
  title 'Virtual edge gateways must be deployed across multiple hypervisor hosts.'
  desc 'An edge gateway is deployed to allow north-south traffic to flow between the virtualized network and the physical network, including destinations outside of the data center or enclave boundaries. The gateway can also filter the north-south traffic to enforce security policies for communication between the physical and virtual workloads. If the edge gateways deployed as virtual machines are resident on the same host, the host becomes a single point of failure for all communication between the virtual workload and the physical network infrastructure. Deploying the edge gateways across multiple hypervisor hosts eliminates the risk of a single point of failure, thereby ensuring there is always reachability between virtual machines and the physical network infrastructure and reducing the risk of black-holing north-south traffic.'
  desc 'check', 'Review the network virtualization platform topology and the SDN manager to verify that each virtual edge gateway has been deployed across multiple hypervisor hosts. 

If each virtual edge gateway has not been deployed across multiple hypervisor hosts, this is a finding.'
  desc 'fix', 'Deploy each virtual edge gateway across multiple hypervisor hosts.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73253r1_chk'
  tag severity: 'low'
  tag gid: 'V-73119'
  tag rid: 'SV-87771r1_rule'
  tag stig_id: 'NET-SDN-028'
  tag gtitle: 'NET-SDN-028'
  tag fix_id: 'F-79565r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
