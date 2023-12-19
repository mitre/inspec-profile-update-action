control 'SV-53733' do
  title 'SQL Server must enforce access control policies to restrict the View any database permission to only authorized roles.'
  desc "The concept of least privilege must be applied to SQL Server processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and SQL Server accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of SQL Server and the OS.

Unauthorized access to sensitive data or SQL Server control may compromise the confidentiality of personnel privacy, threaten national security, compromise a variety of other sensitive operations or lead to a loss of system control. Access controls are best managed by defining requirements based on distinct job functions and assigning access based on the job function assigned to the individual user.

SQL Server's 'View any database' permission is a high server-level privilege that must only be granted to individual administration accounts through roles, and users who have access must require this privilege to accomplish the organizational missions and/or functions. If the 'View any database' permission is granted to roles that are unauthorized to have this privilege, then this access must be removed.

Additionally, the permission must not be denied to a role, because that could disable a user's legitimate access via another role.

The fix for this vulnerability specifies the use of REVOKE.  Be aware that revoking a permission that is currently denied to a role or user does not necessarily disable the permission.  If the user or role can inherent the permission from another role, revoking the denied permission from the user or the first role can effectively enable the inherited permission."
  desc 'check', "Obtain the list of roles that are authorized for the SQL Server 'View any database' permission and what 'Grant', 'Grant With', and/or 'Deny' privilege is authorized. Obtain the list of roles with that permission by running the following query:

SELECT 
       who.name AS [Principal Name],
       who.type_desc AS [Principal Type],
       who.is_disabled AS [Principal Is Disabled],
       what.state_desc AS [Permission State],
       what.permission_name AS [Permission Name]
FROM 
       sys.server_permissions what 
       INNER JOIN sys.server_principals who
              ON who.principal_id = what.grantee_principal_id
WHERE
       what.permission_name = 'View any database' 
AND    who.type_desc = 'SERVER_ROLE'
ORDER BY
       who.name
;
GO 

If any role has 'Grant', 'With Grant' or 'Deny' privileges on this permission and users with that role are not authorized to have the permission, this is a finding.

Alternatively, to provide a combined list for all requirements of this type:
SELECT 
	what.permission_name AS [Permission Name],
	what.state_desc AS [Permission State],
	who.name AS [Principal Name],
	who.type_desc AS [Principal Type],
	who.is_disabled AS [Principal Is Disabled]
FROM 
	sys.server_permissions what 
	INNER JOIN sys.server_principals who
		ON who.principal_id = what.grantee_principal_id
WHERE
	what.permission_name IN
	(
	'Administer bulk operations',
	'Alter any availability group',
	'Alter any connection',
	'Alter any credential',
	'Alter any database',
	'Alter any endpoint ',
	'Alter any event notification ',
	'Alter any event session ',
	'Alter any linked server',
	'Alter any login',
	'Alter any server audit',
	'Alter any server role',
	'Alter resources',
	'Alter server state ',
	'Alter Settings ',
	'Alter trace',
	'Authenticate server ',
	'Control server',
	'Create any database ',
	'Create availability group',
	'Create DDL event notification',
	'Create endpoint',
	'Create server role',
	'Create trace event notification',
	'External access assembly',
	'Shutdown',
	'Unsafe Assembly',
	'View any database',
	'View any definition',
	'View server state'
	)
AND	who.type_desc = 'SERVER_ROLE'
ORDER BY
	what.permission_name,
	who.name
;
GO"
  desc 'fix', %q(Remove the "View any database" permission access from the role that is not authorized by executing the following query:

REVOKE View any database TO <'role name'>)
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47819r5_chk'
  tag severity: 'medium'
  tag gid: 'V-41251'
  tag rid: 'SV-53733r4_rule'
  tag stig_id: 'SQL2-00-007500'
  tag gtitle: 'SRG-APP-000035-DB-000007'
  tag fix_id: 'F-46642r3_fix'
  tag cci: ['CCI-003014']
  tag nist: ['AC-3 (3)']
end
