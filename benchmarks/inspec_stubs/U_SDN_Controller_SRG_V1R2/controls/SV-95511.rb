control 'SV-95511' do
  title 'The SDN controller must be configured to separate tenant functionality from system management functionality.'
  desc 'Network-as-a-Service (NaaS) is frequently offered in a multi-tenant paradigm, where customers share network infrastructure. SDN provides an approach to the provisioning of virtual network services by owners of the network infrastructures to third parties. This leads to various multi-tenancy deployments using different techniques, each of which provides different levels of control while requiring different types of isolation among users. For example, a southbound implementation allows multiple guest controllers sharing the same data forwarding elements; whereas a northbound implementation enables multiple guest applications sharing the whole SDN infrastructure including the SDN controller. To ensure stable network operations in a multi-tenant deployment, it is imperative that the SDN controller is configured to separate tenant functionality from system management functionality.'
  desc 'check', 'Review the SDN controller configuration to determine whether tenant functionality is separated from system management functionality using separated instances within the controller framework as well as Role-based access control (RBAC). 

If the SDN controller is not configured to separate tenant functionality from system management functionality, this is a finding.'
  desc 'fix', 'Configure the SDN controller to have tenant functionality separated from system management functionality using separated instances within the controller framework as well as Role-based access control (RBAC).'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80537r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80801'
  tag rid: 'SV-95511r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001070'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87655r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']
end
