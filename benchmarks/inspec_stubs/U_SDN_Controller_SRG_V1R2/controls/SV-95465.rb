control 'SV-95465' do
  title 'The SDN controller must be configured to enforce approved authorizations for access to system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to system resources within the SDN framework, authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset.

With a multi-tenant implementation, customers share the network infrastructure and services while they are logically isolated from each other. The controller can provide an abstract view of a virtual network that belongs to each tenant. Hence, a northbound multi-tenancy deployment provides tenants with means to manage and monitor their own virtual networks via a northbound API. The behavior of tenants and their end users should be strictly controlled according to pre-defined access policies.  Role-based access control (RBAC) can be implemented to allow tenants to modify configuration and parameters of the SDN framework that they own and control, while prohibiting access to objects they do not own. Tenants have a self-service model by which they can perform configuration changes, read statistics, and monitor logs that apply only to them. To ensure tenant separation while preserving the integrity and stability of the SDN controller, it is imperative that tenant access to resources within the SDN framework is strictly controlled according to access control policies.'
  desc 'check', 'Review the SDN configuration and verify that RBAC rules have been implemented to control access to system resources within the SDN framework. 

If the SDN controller is not configured to enforce approved authorizations for access to system resources, this is a finding.'
  desc 'fix', 'Configure the SDN controller to utilize RBAC rules to enforce approved authorizations for access to system resources.'
  impact 0.5
  ref 'DPMS Target SRG-NET-SDC'
  tag check_id: 'C-80491r1_chk'
  tag severity: 'medium'
  tag gid: 'V-80755'
  tag rid: 'SV-95465r1_rule'
  tag stig_id: 'SRG-NET-000015-SDN-000010'
  tag gtitle: 'SRG-NET-000015'
  tag fix_id: 'F-87609r1_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
