control 'SV-251185' do
  title 'Redis Enterprise DBMS must enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DoD-approved PKI certificate does not necessarily imply authorization to access the DBMS. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DoD-approved PKIs, all DoD systems, including databases, must be properly configured to implement access control policies. 

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement. 

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system. 

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If the DBMS does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', 'Review the system documentation to determine if accounts have been set with appropriate, organizationally defined role-based permissions. Compare these settings with the settings on the actual DB.

To find the database id, run the command:
rladmin status extra all.

1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Verify that each user is assigned an appropriate role.

If a user is not assigned an appropriate role, this is a finding. 

If the appropriate role is not assigned to a user, or the roles and permission settings are not documented, this is a finding.'
  desc 'fix', 'To modify the commands or keys a user is able to access, perform the following steps:

1. Log in to Redis Enterprise.
2. Navigate to the access controls tab.
3. Ensure the appropriate role is configured by inspecting the Redis ACL rules and Roles in the Redis ACL and Role sub-tabs.
4. If an appropriate role is not present, create the appropriate role.
5. On the users tab, assign the appropriate role to the user in question.'
  impact 0.7
  ref 'DPMS Target Redis Enterprise 6.x'
  tag check_id: 'C-54620r804743_chk'
  tag severity: 'high'
  tag gid: 'V-251185'
  tag rid: 'SV-251185r804745_rule'
  tag stig_id: 'RD6X-00-000800'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-54574r804744_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
