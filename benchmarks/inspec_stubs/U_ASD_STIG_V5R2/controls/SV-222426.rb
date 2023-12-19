control 'SV-222426' do
  title 'The application must enforce organization-defined discretionary access control policies over defined subjects and objects.'
  desc 'Discretionary Access Control allows users to determine who is allowed to access their data. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.'
  desc 'check', 'Review the application documentation and interview the application administrator.

Review application data protection requirements and application integrated access control methods.

Identify if the application implements discretionary access control to application resources. Discretionary Access Controls (DAC) allows application users to determine and set permissions on application data and application objects. The result is the user is given the ability to control who has access to the data they control.

If the application does not implement discretionary access controls, this requirement is not applicable.

Resources can be a URL, a folder, a file, a process, a database record, or any other application asset that warrants sharing or authorization permission reassignment.

Create 3 test accounts.

Using test account 1 set protection control on a test user 1 controlled resource.

Grant access to test user 2 and only test user 2.

Authenticate as test user 3 and attempt to access the application resource where test user 1 and test user 2 are granted access. Access should be denied.

If the enforcement of configured access restrictions is not performed, this is a finding.'
  desc 'fix', 'Design and configure the application to enforce discretionary access control policies.'
  impact 0.5
  ref 'DPMS Target Application Security and Development'
  tag check_id: 'C-24096r493186_chk'
  tag severity: 'medium'
  tag gid: 'V-222426'
  tag rid: 'SV-222426r849429_rule'
  tag stig_id: 'APSC-DV-000470'
  tag gtitle: 'SRG-APP-000328'
  tag fix_id: 'F-24085r493187_fix'
  tag 'documentable'
  tag legacy: ['SV-83953', 'V-69331']
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
