control 'SV-255303' do
  title 'Azure SQL Database must enforce approved authorizations for logical access to server information and system resources in accordance with applicable access control policies.'
  desc 'Authentication with a DOD-approved PKI certificate does not necessarily imply authorization to access Azure SQL Database. To mitigate the risk of unauthorized access to sensitive information by entities that have been issued certificates by DOD-approved PKIs, all DOD systems, including databases, must be properly configured to implement access control policies.

Successful authentication must not automatically give an entity access to an asset or security boundary. Authorization procedures and controls must be implemented to ensure each authenticated entity also has a validated and current authorization. Authorization is the process of determining whether an entity, once authenticated, is permitted to access a specific asset. Information systems use access control policies and enforcement mechanisms to implement this requirement.

Access control policies include identity-based policies, role-based policies, and attribute-based policies. Access enforcement mechanisms include access control lists, access control matrices, and cryptography. These policies and mechanisms must be employed by the application to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, and domains) in the information system.

This requirement is applicable to access control enforcement applications, a category that includes database management systems. If Azure SQL Database does not follow applicable policy when approving access, it may be in conflict with networks or other applications in the information system. This may result in users either gaining or being denied access inappropriately and in conflict with applicable policy.'
  desc 'check', "Review the system documentation to determine the required levels of protection for DBMS server securables, by type of login.

Review the permissions actually in place on the server.

Execute the following query to find permissions in place on the server:
SELECT DISTINCT QUOTENAME(sp.name) + ' in server role '
    + QUOTENAME(ISNULL(sp2.name,'Public')) + ' has '
    + QUOTENAME(ISNULL(class_desc,'server'))+ ':'
+ QUOTENAME(ISNULL(object_name(major_id),'~')) + ' permission '
    + QUOTENAME(ISNULL(srvper.permission_name,'-'))
    + '.' COLLATE SQL_Latin1_General_CP1_CI_AS Finding
, object_name(major_id) ObjectName
FROM sys.database_principals sp
LEFT JOIN sys.database_role_members srm ON sp.principal_id = srm.member_principal_id
LEFT JOIN sys.database_principals sp2 ON srm.role_principal_id = sp2.principal_id
LEFT JOIN sys.database_permissions srvper ON srvper.grantee_principal_id = sp.principal_id
WHERE sp.type IN ('u','s','g') --Windows/Sql/Groups
AND sp.principal_id <> 1

If the actual permissions do not match the documented requirements, this is a finding."
  desc 'fix', 'Use GRANT, REVOKE, DENY, ALTER SERVER ROLE … ADD MEMBER … and/or ALTER SERVER ROLE …. DROP MEMBER statements to add and remove permissions on server-level securables, bringing them in line with the documented requirements.

References:
Revoke:
https://docs.microsoft.com/en-us/sql/t-sql/statements/revoke-transact-sql?view=azuresqldb-current

Deny:
https://docs.microsoft.com/en-us/sql/t-sql/statements/deny-transact-sql?view=azuresqldb-current

DROP MEMBER:
https://docs.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/sp-droprolemember-transact-sql?view=azuresqldb-current'
  impact 0.7
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58976r871033_chk'
  tag severity: 'high'
  tag gid: 'V-255303'
  tag rid: 'SV-255303r871035_rule'
  tag stig_id: 'ASQL-00-000300'
  tag gtitle: 'SRG-APP-000033-DB-000084'
  tag fix_id: 'F-58920r871034_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
