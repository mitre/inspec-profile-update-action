control 'SV-214033' do
  title 'SQL Server execute permissions to access the registry must be revoked, unless specifically required and approved.'
  desc "Information systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). 

It is detrimental for applications to provide, or install by default, functionality exceeding requirements or mission objectives. 

Applications must adhere to the principles of least functionality by providing only essential capabilities.

SQL Server may spawn additional external processes to execute procedures that are defined in the SQL Server but stored in external host files (external procedures). The spawned process used to execute the external procedure may operate within a different OS security context than SQL Server and provide unauthorized access to the host system.

The registry contains sensitive information, including password hashes as well as clear text passwords. Registry extended stored procedures allow Microsoft SQL Server to access the machine's registry. The sensitivity of these procedures are exacerbated if Microsoft SQL Server is run under the Windows account LocalSystem. LocalSystem can read and write nearly all values in the registry, even those not accessible by the Administrator. Unlike the xp_cmdshell extended stored procedure, which runs under a separate context if executed by a login not in the sysadmin role, the registry extended stored procedures always execute under the security context of the MSSQLServer service. Because the sensitive information is stored in the registry, it is essential that access to that information be properly guarded."
  desc 'check', "To determine if permissions to execute registry extended stored procedures have been revoked from all users (other than dbo), execute the following command:

SELECT OBJECT_NAME(major_id) AS [Stored Procedure]
,dpr.NAME AS [Principal]
FROM sys.database_permissions AS dp
INNER JOIN sys.database_principals AS dpr ON dp.grantee_principal_id = dpr.principal_id
WHERE major_id IN (
 OBJECT_ID('xp_regaddmultistring')
,OBJECT_ID('xp_regdeletekey')
,OBJECT_ID('xp_regdeletevalue')
,OBJECT_ID('xp_regenumvalues')
,OBJECT_ID('xp_regenumkeys')
,OBJECT_ID('xp_regremovemultistring')
,OBJECT_ID('xp_regwrite')
,OBJECT_ID('xp_instance_regaddmultistring')
,OBJECT_ID('xp_instance_regdeletekey')
,OBJECT_ID('xp_instance_regdeletevalue')
,OBJECT_ID('xp_instance_regenumkeys')
,OBJECT_ID('xp_instance_regenumvalues')
,OBJECT_ID('xp_instance_regremovemultistring')
,OBJECT_ID('xp_instance_regwrite')
)
AND dp.[type] = 'EX'
ORDER BY dpr.NAME;

If any records are returned, review the system documentation to determine whether the accessing of the registry via  extended stored procedures are required and authorized. If it is not authorized, this is a finding."
  desc 'fix', 'Remove execute permissions to any registry extended stored procedure from all users (other than dbo).

USE master
GO
REVOKE EXECUTE ON [<procedureName>] FROM [<principal>]
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15250r313882_chk'
  tag severity: 'medium'
  tag gid: 'V-214033'
  tag rid: 'SV-214033r879587_rule'
  tag stig_id: 'SQL6-D0-016700'
  tag gtitle: 'SRG-APP-000141-DB-000093'
  tag fix_id: 'F-15248r313883_fix'
  tag 'documentable'
  tag legacy: ['SV-94033', 'V-79327']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
