control 'SV-254089' do
  title 'Innoslate must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems (e.g., networks, web servers, and web portals) must be properly configured to incorporate access control methods that do not rely solely on the possession of a certificate for access. Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications (e.g., authentication servers) and other applications that perform information and system access control functions.

Steps to prove capability:

1. Sign in as admin.
2. Enter the admin dashboard.
3. Select the respective org name on the left.
4. View the users and validate the correct permissions are applied.
5. View the roles and validate they are correct.
6. Enter a project.
7. Click "Share".
8. Verify the correct users are shared with the correct roles to the project.

'
  desc 'check', '1. Sign in With Admin Account.
2. Enter Admin Dashboard.
3. Click on the "Organization" tab.
4. Find the "Roles" section.
5. Select the role to verify.
6. Ensure Administrative roles are separated from End User roles. Otherwise, this is a finding.'
  desc 'fix', '1. Sign in With Admin Account.
2. Enter Admin Dashboard.
3. Click on the "Organization" tab.
4. Find the "Roles" section.
5. Select the role to verify.
6. Verify via checkboxes that the role has the correct permissions applied.
7. Click "Edit" if changes are needed.
8. Select the appropriate role permissions to separate Administrative Users from End Users.
9. Click "Update".
10. Verify changes were made.'
  impact 0.5
  ref 'DPMS Target SPEC Innovations Innoslate 4.x'
  tag check_id: 'C-57574r845241_chk'
  tag severity: 'medium'
  tag gid: 'V-254089'
  tag rid: 'SV-254089r845243_rule'
  tag stig_id: 'SPEC-IN-000080'
  tag gtitle: 'SRG-APP-000033'
  tag fix_id: 'F-57525r845242_fix'
  tag satisfies: ['SRG-APP-000033', 'SRG-APP-000039', 'SRG-APP-000090', 'SRG-APP-000343']
  tag 'documentable'
  tag cci: ['CCI-000171', 'CCI-000213', 'CCI-001414', 'CCI-002234']
  tag nist: ['AU-12 b', 'AC-3', 'AC-4', 'AC-6 (9)']
end
