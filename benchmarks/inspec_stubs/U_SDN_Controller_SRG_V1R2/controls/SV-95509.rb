control 'SV-95509' do
  title 'The SDN controller must be configured to enable multi-tenant virtual networks to be fully isolated from one another.'
  desc 'Network-as-a-Service (NaaS) is often implemented in a multi-tenant paradigm, where customers share network infrastructure and services while they are logically isolated from each other. SDN provides an approach to the orchestration and provisioning of virtual network services by the owners of the network infrastructures. This leads to various multi-tenancy deployments: on different layers, for different purposes, using different techniques—each of which provides different levels of control while requiring different types of isolation among users. For instance, implementation can be a southbound multi-tenancy with several guest controllers sharing the same data forwarding elements, or a northbound multi-tenancy with several guest applications sharing the entire SDN infrastructure including the SDN controller. Regardless of the implementation, it is imperative that the controller provides the necessary isolation and separation.'
  desc 'check', 'Review the SDN controller configuration to determine if it is configured to deploy dedicated instances of virtual networks and separate forwarding tables to the provisioned network elements belonging to each tenant. 

If the SDN Controller is not configured to enable multi-tenant virtual networks to be fully isolated from one another, this is a finding.'
  desc 'fix', 'Configure the SDN controller to deploy dedicated instances of virtual networks and separate forwarding tables to the provisioned network elements belonging to each tenant.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80535r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80799'
  tag rid: 'SV-95509r1_rule'
  tag stig_id: 'SRG-NET-000512-SDN-001065'
  tag gtitle: 'SRG-NET-000512'
  tag fix_id: 'F-87653r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
