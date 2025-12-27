control 'SV-222425' do
  title 'The application must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. 

Successful authentication must not automatically give an entity access to a restricted asset or security boundary.

Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization.

Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset.

Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies.

Access enforcement mechanisms include access control lists, access control matrices, and cryptography.

These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Review application data protection requirements.

Identify application resources that require protection and authentication over and above the authentication required to access the application itself.

This can be access to a URL, a folder, a file, a process or a database record that should only be available to certain individuals.

Identify the access control methods utilized by the application in order to control access to the resource.

Examples include Role-Based Access Control policies (RBAC).

Using RBAC as an example, utilize a test account placed into a test role.

Set a protection control on a resource and explicitly deny access to the role assigned to the test user account.

Try to access an application resource that is not configured to allow access. Access should be denied.

If the enforcement of configured access restrictions is not performed, this is a finding.'
  desc 'fix', 'Design or configure the application to enforce access to application resources.'
  impact 0.7
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24095r493183_chk'
  tag severity: 'high'
  tag gid: 'V-222425'
  tag rid: 'SV-222425r879530_rule'
  tag stig_id: 'APSC-DV-000460'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-24084r493184_fix'
  tag 'documentable'
  tag legacy: ['SV-83951', 'V-69329']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
