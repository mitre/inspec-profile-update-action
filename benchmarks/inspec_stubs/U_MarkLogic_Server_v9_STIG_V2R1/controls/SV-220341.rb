control 'SV-220341' do
  title 'MarkLogic Server must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.

MarkLogic Server uses a role-based security model. A user’s privileges and permissions are based on the roles assigned to the user. For background information on understanding the security model in MarkLogic Server, see Security Guide.'
  desc 'check', 'Check MarkLogic settings to determine whether users are restricted from accessing objects and data they are not authorized to access.

Perform the check from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click on the Security Icon.
2. Click the Users Icon.
3. Click on a User, and then click the Describe tab.
4. Verify the User has the appropriate Roles assigned per organization/user requirements and system documentation.
5. If the User is missing a required role or possesses a Role they do not require, this is a finding.
6. Repeat for all added Users.'
  desc 'fix', 'Configure MarkLogic settings and access controls to permit user access only to objects and data the user is authorized to view or interact with, and to prevent access to all other objects and data.

Perform the fix from the MarkLogic Server Admin Interface with a user that holds administrative-level privileges.

1. Click the Security Icon.
2. Click the Users Icon.
3. Select one of the added Users with a misconfigured set of Security Roles.
4. Either add or remove Security Role(s) as required per organization/user requirements and system documentation.
5. Click OK.
6. Repeat actions above for all misconfigured Users.'
  impact 0.7
  ref 'DPMS Target MarkLogic Server v9'
  tag check_id: 'C-22056r401474_chk'
  tag severity: 'high'
  tag gid: 'V-220341'
  tag rid: 'SV-220341r622777_rule'
  tag stig_id: 'ML09-00-000300'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-22045r401475_fix'
  tag 'documentable'
  tag legacy: ['SV-110029', 'V-100925']
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
