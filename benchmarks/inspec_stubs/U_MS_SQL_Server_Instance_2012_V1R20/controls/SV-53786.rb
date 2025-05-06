control 'SV-53786' do
  title 'SQL Server must enforce non-DAC policies over users and resources where the policy rule set for each policy specifies access control information (i.e., position, nationality, age, project, time of day).'
  desc 'Non-DAC controls are determined by policy makers and are managed centrally or by a central authority. These controls must not be changed at the discretion of ordinary application users. Data protection requirements may result in a non-DAC policy being specified as part of the application design. Non-DACs are employed at the application level to restrict and control access to application data, thereby providing increased information security for the organization.

SQL Server Non-DAC is maintained through the use of Roles. Roles are set up within SQL Server to grant user accounts read and/or write permissions to system objects: databases, tables, columns, etc. After a role is created, user accounts can be assigned to a role granting them permissions of that role.

If users have permissions to database objects that they are not authorized to have, the user account that has access to the unauthorized database object must be removed from the role that grants that access. Policy rule sets would be developed to establish that each user receives only the information to which the user is authorized.

Frequently, roles grant access to multiple privileges; if a user is authorized and determined to need access to authorized privilege granted by a role, and unauthorized for other privileges of that same role, it may be necessary to split the privileges of one role into two roles.'
  desc 'check', %q(Check for direct user assignment to server permissions by running the following script:
/**********************************************************************************
LIST ALL DIRECT SERVER PERMISSIONS TO ANY ACCOUNT EXCEPT
SYSTEM ADMINISTRATOR ACCOUNTS.  DO NOT LIST ROLES.
***********************************************************************************/
DECLARE @admin_Account_name sysname
SET @admin_Account_name = 'NO administrator account found'
DECLARE @server_name sysname
SET @server_name = 'NO Server found'

SELECT @server_name = name FROM sys.servers
WHERE server_id = 0
SET @admin_Account_name = @server_name + '\Administrator'

SELECT pe.grantee_principal_id
, pr.type AS 'Grantee_Type'
, pr.name AS 'Grantee_Name'
, pe.type
, pe.permission_name
, pe.state
, pe.state_desc
FROM sys.server_permissions pe
JOIN sys.server_principals pr
ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals ps
ON pe.grantor_principal_id = ps.principal_id
LEFT JOIN sys.server_principals us
ON us.principal_id = pe.major_id
WHERE pr.type IN ('K', 'S', 'U')
AND pe.grantee_principal_id > 10
AND NOT pr.name IN ('##MS_PolicyEventProcessingLogin##', '##MS_PolicyTsqlExecutionLogin##',
'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\MSSQLSERVER',
'NT SERVICE\SQLSERVERAGENT', 'NT SERVICE\SQLWriter', 'NT SERVICE\Winmgmt')
AND NOT pr.name = @admin_Account_name
AND NOT pe.permission_name = 'connect sql'
ORDER BY CASE pr.type
WHEN 'K' THEN 1
WHEN 'S' THEN 2
WHEN 'U' THEN 3
ELSE 4
END;
GO

If any user account listed indicates direct access to any server permission, this is a finding.

Obtain the list of available user-defined server roles from system documentation.

Obtain the list of available user-defined server roles from the SQL Server system by running the following script:
/**********************************************************************************
 LIST ALL INDIRECT (via ROLES) ACCESS TO THE SERVER PERMISSION.
 ***********************************************************************************/
DECLARE @admin_Account_name sysname
SET @admin_Account_name = 'NO admin ACCOUNT found'
DECLARE @server_name sysname
SET @server_name = 'NO Server found'

SELECT @server_name = name FROM sys.servers
WHERE server_id = 0
SET @admin_Account_name = @server_name + '\Administrator'

SELECT pe.grantee_principal_id
, pr.type AS 'Grantee_Type'
, pr.name AS 'Grantee_Name'
, pe.type
, pe.permission_name
, pe.state
, pe.state_desc
FROM sys.server_permissions pe
JOIN sys.server_principals pr
ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals ps
ON pe.grantor_principal_id = ps.principal_id
LEFT JOIN sys.server_principals us
ON us.principal_id = pe.major_id
WHERE pr.type IN ('R')
AND pe.grantee_principal_id > 10
AND NOT pr.name IN ('##MS_PolicyEventProcessingLogin##', '##MS_PolicyTsqlExecutionLogin##',
'NT AUTHORITY\NETWORK SERVICE', 'NT AUTHORITY\SYSTEM', 'NT SERVICE\MSSQLSERVER',
'NT SERVICE\SQLSERVERAGENT', 'NT SERVICE\SQLWriter', 'NT SERVICE\Winmgmt')
AND NOT pr.name = @admin_Account_name
AND NOT pe.permission_name = 'connect sql'
ORDER BY CASE pe.state
WHEN 'D' THEN 1
WHEN 'W' THEN 2
WHEN 'G' THEN 3
ELSE 4
END;
GO

Obtain the list of user role assignments in the system documentation.

Check all SQL Server user-defined server roles for authorized and documented permission assignments. Repeat steps for each user-defined server role.
Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Server Roles >> right click <'user-defined server role name'> >> Properties >> Members.

If both user-defined role(s) and user(s) are listed as "Member of this role", this is a propagation of access rights, and this is a finding.)
  desc 'fix', "Add the user as a member of the user-defined server role within the system documentation.

Remove the user from direct access to server permission by running the following script:
USE master
REVOKE <'server permission name'> TO <'account name'> CASCADE

Remove the user from user-defined role access by running the following script:
USE master
ALTER SERVER ROLE [<'server role name'>] DROP MEMBER <'user name'>"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47873r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41304'
  tag rid: 'SV-53786r4_rule'
  tag stig_id: 'SQL2-00-002200'
  tag gtitle: 'SRG-APP-000035-DB-000007'
  tag fix_id: 'F-46695r2_fix'
  tag 'documentable'
  tag cci: ['CCI-003014']
  tag nist: ['AC-3 (3)']
end
