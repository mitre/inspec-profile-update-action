control 'SV-255316' do
  title 'Azure SQL Database must enforce discretionary access control policies, as defined by the data owner, over defined subjects and objects.'
  desc 'Discretionary Access Control (DAC) is based on the notion that individual users are "owners" of objects and therefore have discretion over who should be authorized to access the object and in which mode (e.g., read, write, execute). Ownership is usually acquired implicitly when creating the object or by explicit ownership assignment. DAC allows the owner to determine who will have access to objects they control and the permissions related to that access. An example of DAC includes user-controlled table permissions.

When DAC policies are implemented, subjects are not constrained with regard to what actions they can take with information for which they have already been granted access. Thus, subjects that have been granted access to information are not prevented from passing (i.e., the subjects have the discretion to pass) the information to other subjects or objects.

A subject that is constrained in its operation by Mandatory Access Control policies is still able to operate under the less rigorous constraints of this requirement. Thus, while Mandatory Access Control imposes constraints preventing a subject from passing information to another subject operating at a different sensitivity level, this requirement permits the subject to pass the information to any subject at the same sensitivity level.

The policy is bounded by the information system boundary. Once the information is passed outside of the control of the information system, additional means may be required to ensure the constraints remain in effect. While the older, more traditional definitions of DCA require identity-based access control, that limitation is not required for this use of discretionary access control.'
  desc 'check', "Review application or system documentation to identify the required DAC.

Review the security configuration of the database. If applicable, review the security configuration of the application(s) using the database.

If the DAC defined in the documentation is not implemented in the security configuration, this is a finding.

Validate database object ownership using the queries below:

View object ownership - All objects and schemas

SELECT object_id, 
SCHEMA_NAME(schema_id) AS SchemaName,
[name] AS Securable,
USER_NAME(principal_id) AS ObjectOwner,
[type_desc] AS ObjectType
FROM sys.objects
WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
ORDER BY ObjectType, Securable, ObjectOwner

View object ownership - Specific object

DECLARE @ObjectName nvarchar(512)
SET @ObjectName = '' --Specify object name here
SELECT object_id, 
SCHEMA_NAME(schema_id) AS SchemaName,
[name] AS Securable,
USER_NAME(principal_id) AS ObjectOwner,
[type_desc] AS ObjectType
FROM sys.objects
WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
AND [name] = @ObjectName
ORDER BY ObjectType, Securable, ObjectOwner

View object ownership - Specific schema

DECLARE @SchemaName nvarchar(512)
SET @SchemaName = '' --Specify schema name here
SELECT object_id, 
SCHEMA_NAME(schema_id) AS SchemaName,
[name] AS Securable,
USER_NAME(principal_id) AS ObjectOwner,
[type_desc] AS ObjectType
FROM sys.objects
WHERE is_ms_shipped = 0 AND principal_id IS NOT NULL
AND SCHEMA_NAME(schema_id) = @SchemaName
ORDER BY ObjectType, Securable, ObjectOwner

Schemas not owned by the schema or [dbo]

SELECT [name] AS [SchemaName], USER_NAME(principal_id) AS [SchemaOwner]
FROM sys.schemas
WHERE schema_id != principal_id --exclude schemas owned by the schema
AND principal_id != 1 --exclude schema dbo

Database principals delegated the right to assign additional permissions

SELECT U.type_desc AS [PrincipalType],
 U.name AS [Grantee],
DP.class_desc AS [SecurableType],
CASE DP.class
    WHEN 0 THEN DB_NAME()
    WHEN 1 THEN OBJECT_NAME(DP.major_id)
    WHEN 3 THEN SCHEMA_NAME(DP.major_id)
ELSE CAST(DP.major_id AS nvarchar)
    END AS [Securable],
permission_name AS [PermissionName],
state_desc AS [DelegatedRight]
FROM sys.database_permissions DP
JOIN sys.database_principals U ON DP.grantee_principal_id = U.principal_id
WHERE DP.state = 'W'
ORDER BY Grantee, SecurableType, Securable

If any of these rights are not documented and authorized, this is a finding."
  desc 'fix', 'To correct object ownership:
Use the ALTER AUTHORIZATION ON::[Object Name] TO [Database principal] TSQL statement to correct object ownership. Full ALTER AUTHORIZATION command syntax is described in this document: ALTER AUTHORIZATION (Transact-SQL) - SQL Server | Microsoft Docs (https://docs.microsoft.com/en-us/sql/t-sql/statements/revoke-transact-sql?view=azuresqldb-current)

To remove unauthorized permissions:
Use the REVOKE [Permission name] ON [Object name] TO [Database principal] to remove unauthorized permissions from a database principal on an object. Full REVOKE command syntax is described in this document: REVOKE (Transact-SQL) - SQL Server | Microsoft Docs (https://docs.microsoft.com/en-us/sql/t-sql/statements/alter-authorization-transact-sql?view=azuresqldb-current)'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58989r871072_chk'
  tag severity: 'medium'
  tag gid: 'V-255316'
  tag rid: 'SV-255316r871074_rule'
  tag stig_id: 'ASQL-00-002800'
  tag gtitle: 'SRG-APP-000328-DB-000301'
  tag fix_id: 'F-58933r871073_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
