control 'SV-53672' do
  title 'SQL Server must enforce DAC policy allowing users to specify and control sharing by named individuals, groups of individuals, or by both; limiting propagation of access rights; and including or excluding access to the granularity of a single user.'
  desc 'Access control policies (e.g., identity-based policies, role-based policies, attribute-based policies) and access enforcement mechanisms (e.g., access control lists, access control matrices, cryptography) are employed by organizations to control access between users (or processes acting on behalf of users) and objects (e.g., devices, files, records, processes, programs, domains).

DAC is a type of access control methodology serving as a means of restricting access to objects and data based on the identity of subjects and/or groups to which they belong. It is discretionary in the sense that application users with the appropriate permissions to access an application resource or data have the discretion to pass that permission on to another user either directly or indirectly.

Data protection requirements may result in a DAC policy being specified as part of the application design. Discretionary access controls would be employed at the application level to restrict and control access to application objects and data, thereby providing increased information security for the organization.

When DAC controls are employed, those controls must limit sharing to named application users, groups of users, or both. The application DAC controls must also limit the propagation of access rights and have the ability to exclude access to data down to the granularity of a single user.

Databases using DAC must have the ability for the owner of an object or information to assign or revoke rights to view or modify the object or information. If the owner of an object or information does not have rights to exclude access to an object or information at a user level, users may gain access to objects and information they are not authorized to view/modify.'
  desc 'check', "Check for direct user assignment to server permissions by running the following script:
/**********************************************************************************
 LIST ALL DIRECT SERVER PERMISSIONS TO ANY ACCOUNT EXCEPT
  SYSTEM ADMINISTRATOR accounts.  DO NOT LIST ROLES.
***********************************************************************************/
DECLARE @admin_Account_name sysname
SET @admin_Account_name = 'NO Administrator account found'
DECLARE @server_name sysname
SET @server_name = 'NO Server found'

SELECT @server_name = name FROM sys.servers
 WHERE server_id = 0
SET @admin_Account_name = @server_name  + '\\Administrator'

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
                       'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM', 'NT SERVICE\\MSSQLSERVER',
                       'NT SERVICE\\SQLSERVERAGENT', 'NT SERVICE\\SQLWriter', 'NT SERVICE\\Winmgmt')
   AND NOT pr.name = @admin_Account_name
 ORDER BY CASE pr.type
             WHEN 'K' THEN 1
             WHEN 'S' THEN 2
             WHEN 'U' THEN 3
             ELSE 4
          END

If any user account list indicates direct access to any server permission, this is a finding.

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
SET @admin_Account_name = @server_name  + '\\Administrator'

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
                       'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM', 'NT SERVICE\\MSSQLSERVER',
                       'NT SERVICE\\SQLSERVERAGENT', 'NT SERVICE\\SQLWriter', 'NT SERVICE\\Winmgmt')
   AND NOT pr.name = @admin_Account_name
 ORDER BY CASE pe.state
             WHEN 'D' THEN 1
             WHEN 'W' THEN 2
             WHEN 'G' THEN 3
             ELSE 4
          END

If any listed user-defined roles are not found in the system documentation, this is a finding.

Obtain the list of user role assignments in the system documentation.

Check all SQL Server user-defined server roles for authorized and documented permission assignments. Repeat steps for each user-defined server role.
Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Server Roles >> right click <'user-defined server role name'> >> Properties >> Members.  If any roles are found that are not authorized and documented, this is a finding."
  desc 'fix', "Add the user-defined server role to the system documentation.

Add the user as a member of the user-defined server role within the system documentation.

Remove the user from direct access to server permission by running the following script:
USE master
REVOKE <'server permission name'> TO <'account name'> CASCADE

Remove the user from user-defined role access by running the following script:
USE master
ALTER SERVER ROLE [<'server role name'>] DROP MEMBER <'user name'>

Add the user-defined role access to the user by running the following script:
USE master
ALTER SERVER ROLE [<'server role name'>] ADD  MEMBER <'user name'>"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47795r4_chk'
  tag severity: 'medium'
  tag gid: 'V-41205'
  tag rid: 'SV-53672r3_rule'
  tag stig_id: 'SQL2-00-008500'
  tag gtitle: 'SRG-APP-000036-DB-000174'
  tag fix_id: 'F-46597r2_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
