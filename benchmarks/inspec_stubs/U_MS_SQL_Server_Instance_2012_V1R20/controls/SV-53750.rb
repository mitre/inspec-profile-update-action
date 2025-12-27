control 'SV-53750' do
  title 'SQL Server must not grant users direct access to the Control server permission.'
  desc "The concept of least privilege must be applied to SQL Server processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and SQL Server accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of SQL Server and the OS.

Unauthorized access to sensitive data or SQL Server control may compromise the confidentiality of personnel privacy, threaten national security, compromise a variety of other sensitive operations or lead to a loss of system control. Access controls are best managed by defining requirements based on distinct job functions and assigning access based on the job function assigned to the individual user.

Privileges granted outside of SQL Server's role-based account assignments are more likely to go unmanaged and without oversight of granted access. Maintenance of privileges using roles defined for discrete job functions offers improved oversight of application user privilege assignments and helps to protect against unauthorized privilege assignment.

SQL Server's 'Control server' permission is a high server-level privilege that must only be granted to individual administration accounts through roles. This administrative privilege must not be assigned directly to administrative user accounts (or any other user accounts). If any user accounts have direct access to administrative privileges, this access must be removed.

Note that this does not apply to logins with names of the form '##MS...##'.  These accounts are internal-use system principals provisioned by the DBMS, and required by it for specific purposes."
  desc 'check', "Obtain the list of accounts that have direct access to the server-level permission 'Control server' by running the following query:

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
       what.permission_name = 'Control server'
AND    who.name NOT LIKE '##MS%##'
AND    who.type_desc <> 'SERVER_ROLE'
ORDER BY
       who.name
;
GO

If any user accounts have direct access to the 'Control server' permission, this is a finding.

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
AND    who.name NOT LIKE '##MS%##'
AND    who.type_desc <> 'SERVER_ROLE'
ORDER BY
	what.permission_name,
	who.name
;
GO"
  desc 'fix', "Remove the 'Control server' permission access from the account that has direct access by running the following script:


USE master

REVOKE CONTROL SERVER TO <'account name'>

GO"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47836r5_chk'
  tag severity: 'medium'
  tag gid: 'V-41268'
  tag rid: 'SV-53750r4_rule'
  tag stig_id: 'SQL2-00-005800'
  tag gtitle: 'SRG-APP-000035-DB-000007'
  tag fix_id: 'F-46659r1_fix'
  tag cci: ['CCI-003014']
  tag nist: ['AC-3 (3)']
end
