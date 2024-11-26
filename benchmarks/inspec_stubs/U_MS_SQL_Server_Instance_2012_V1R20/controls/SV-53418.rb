control 'SV-53418' do
  title 'Administrators must utilize a separate, distinct administrative account when performing administrative activities, accessing database security functions, or accessing security-relevant information within SQL Server.'
  desc 'This requirement is intended to limit exposure due to operating from within a privileged account or role. The inclusion of role is intended to address those situations where an access control policy, such as Role-Based Access Control (RBAC), is being implemented and where a change of role provides the same degree of assurance in the change of access authorizations for both the user and all processes acting on behalf of the user as would be provided by a change between a privileged and non-privileged account.

To limit exposure when operating from within a privileged account or role, SQL Server does support organizational requirements that users of information system accounts, or roles, with access to an organization-defined list of security functions or security-relevant information, use non-privileged accounts, or roles, when accessing other (non-security) system functions.

When privileged activities are not separated from non-privileged activities, SQL Server could be subject to unauthorized changes of settings or data, which a standard user would not normally have access to outside of an authorized maintenance session. Often, administrator accounts have a unique prefix to help with identification. These accounts are located within SQL Server and may only provide access to one database instance or a limited number of database objects.'
  desc 'check', "Obtain a list of SQL Server DBAs or other administrative accounts. Run the following SQL script to check all users’ permissions:

SELECT SP1.[name] AS 'Login', 'Role: ' + SP2.[name] COLLATE DATABASE_DEFAULT AS 'ServerPermission'
FROM sys.server_principals SP1
  JOIN sys.server_role_members SRM
    ON SP1.principal_id = SRM.member_principal_id
  JOIN sys.server_principals SP2
    ON SRM.role_principal_id = SP2.principal_id
UNION ALL
SELECT SP.[name] AS 'Login' , SPerm.state_desc + ' ' + SPerm.permission_name COLLATE DATABASE_DEFAULT AS 'ServerPermission'
  FROM sys.server_principals SP
  JOIN sys.server_permissions SPerm
    ON SP.principal_id = SPerm.grantee_principal_id
ORDER BY [Login], [ServerPermission]

If any DBA or administrative objects are owned by non-DBA or non-administrative accounts, this is a finding.

If any DBA or administrator has authorization for non- administrative access to the system for which they are the administrator and they do not have a non-administrator account, this is a finding."
  desc 'fix', "Remove DBA privileges and privileges to administer owned objects that are assigned to the administrator's non-DBA account.
Remove the permission access from the account that has direct access by running the following script:
USE master
REVOKE <'server privilege name'> TO <'account name'>
GO

Remove the user account from the role's Member list where the account is not authorized for specified permission by running the following script:
USE master
ALTER SERVER ROLE [<'server role name'>] DROP MEMBER <'user name'>
GO

Provide administrators with separate accounts for administration and regular accounts for non-administrator activity."
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47660r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41043'
  tag rid: 'SV-53418r2_rule'
  tag stig_id: 'SQL2-00-009600'
  tag gtitle: 'SRG-APP-000063-DB-000017'
  tag fix_id: 'F-46342r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
