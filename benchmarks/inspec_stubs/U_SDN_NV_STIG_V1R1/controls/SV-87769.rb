control 'SV-87769' do
  title 'Two or more edge gateways must be deployed connecting the network virtualization platform (NVP) and the physical network.'
  desc 'An edge gateway is deployed to allow north-south traffic to flow between the virtualized network and the physical network, including destinations outside of the data center or enclave boundaries. The gateway establishes routing adjacencies between the virtual routers and physical routers. The gateway can also filter the north-south traffic to enforce security policies for communication between the physical and virtual workloads. Deploying two or more edge gateways eliminates the risk of a single point of failure, thereby ensuring there is always reachability between virtual machines and the physical network infrastructure and reducing the risk of black-holing north-south traffic.'
  desc 'check', 'Review the network topology diagram for both the physical infrastructure and the NVP to determine if two or more edge gateways have been deployed between the virtual and physical networks. 

If two or more edge gateways connecting the NVP and the physical network have not been deployed, this is a finding.

Note: This requirement is not applicable if hardware switches are deployed as VTEP devices that also function as gateways between VXLANs and between VXLAN and non-VXLAN infrastructures.'
  desc 'fix', 'Deploy two or more edge gateways connecting the network virtualization platform and the physical network.'
  impact 0.3
  ref 'DPMS Target Software Defined Networking (SDN) Policy'
  tag check_id: 'C-73251r1_chk'
  tag severity: 'low'
  tag gid: 'V-73117'
  tag rid: 'SV-87769r1_rule'
  tag stig_id: 'NET-SDN-027'
  tag gtitle: 'NET-SDN-027'
  tag fix_id: 'F-79563r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
