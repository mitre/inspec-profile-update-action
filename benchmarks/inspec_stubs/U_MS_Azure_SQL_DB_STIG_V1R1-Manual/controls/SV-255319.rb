control 'SV-255319' do
  title 'Azure SQL Database must enforce access restrictions associated with changes to the configuration of the Azure SQL Database server or database(s).'
  desc 'Failure to provide logical access restrictions associated with changes to configuration may have significant effects on the overall security of the system. 

When dealing with access restrictions pertaining to change control, it should be noted that any changes to the hardware, software, and/or firmware components of the information system can potentially have significant effects on the overall security of the system. 

Accordingly, only qualified and authorized individuals must be allowed to obtain access to system components for the purposes of initiating changes, including upgrades and modifications.'
  desc 'check', "Obtain a list of logins who have privileged permissions and role memberships in the data and control planes of Azure SQL Database.

For Database Permissions:

SELECT P.type_desc AS principal_type, P.name AS principal_name,
O.type_desc,
CASE class
WHEN 0 THEN DB_NAME()
WHEN 1 THEN OBJECT_SCHEMA_NAME(major_id) + '.' + OBJECT_NAME(major_id)
WHEN 3 THEN SCHEMA_NAME(major_id)
ELSE class_desc + '(' + CAST(major_id AS nvarchar) + ')'
END AS securable_name, DP.state_desc, DP.permission_name
FROM sys.database_permissions DP
JOIN sys.database_principals P ON DP.grantee_principal_id = P.principal_id
LEFT OUTER JOIN sys.all_objects O ON O.object_id = DP.major_id AND O.type IN ('TR','TA','P','X','RF','PC','IF','FN','TF','U')
WHERE DP.type IN ('AL','ALTG') AND DP.class IN (0, 1, 53)

For Database Role Memberships:

SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
AND M.name != 'dbo'

For Control Plane Role Memberships, run in PowerShell:

$AzureSqlDbName = '<Azure SQL Database Name>'
$AzureSqlDbResourceID = Get-AzResource -Name $AzureSqlDbName
Get-AzRoleAssignment -Scope $AzureSqlDbResourceID.ResourceId -IncludeClassicAdministrators | Format-Table DisplayName,RoleDefinitionName 

Check the documentation to verify the logins and roles returned are authorized. If the logins and/or roles are not documented and authorized, this is a finding."
  desc 'fix', 'Document and obtain approval for logins with privileged permissions and role memberships.

If necessary, use the ALTER ROLE and/or REVOKE commands to remove unauthorized privileged permissions and/or role memberships. Example provided below.

ALTER ROLE ddladmin DROP MEMBER UnauthorizedUser;  

REVOKE SELECT ON OBJECT::test.table FROM UnauthorizedUser;

https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-role-transact-sql

https://docs.microsoft.com/en-us/sql/t-sql/statements/revoke-transact-sql

If necessary, in the Azure Portal, navigate to the Access Control pane for the Azure SQL Database to review and remove unauthorized privileged permissions and/or role memberships. Refer to link to documentation below.

https://docs.microsoft.com/en-us/azure/role-based-access-control/role-definitions-list

https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-remove'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58992r877252_chk'
  tag severity: 'medium'
  tag gid: 'V-255319'
  tag rid: 'SV-255319r877253_rule'
  tag stig_id: 'ASQL-00-003100'
  tag gtitle: 'SRG-APP-000380-DB-000360'
  tag fix_id: 'F-58936r871082_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
