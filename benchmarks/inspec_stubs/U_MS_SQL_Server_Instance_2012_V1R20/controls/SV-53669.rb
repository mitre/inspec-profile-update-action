control 'SV-53669' do
  title 'SQL Server must enforce separation of duties through assigned information access authorizations.'
  desc 'Separation of duties is a prevalent Information Technology control that is implemented at different layers of the information system, including the operating system and in applications. It serves to eliminate or reduce the possibility that a single user may carry out a prohibited action. Separation of duties requires that the person accountable for approving an action is not the same person who is tasked with implementing or carrying out that action.

Additionally, the person or entity accountable for monitoring the activity must be separate as well. To meet this requirement, applications, when applicable, shall be divided where functionality is based on roles and duties. Examples of separation of duties include: (i) mission functions and distinct information system support functions are divided among different individuals/roles; (ii) different individuals perform information system support functions (e.g., system management, systems programming, configuration management, quality assurance and testing, network security); (iii) security personnel who administer access control functions do not administer audit functions; and (iv) different administrator accounts for different roles.

Privileges granted outside the role of the application user job function are more likely to go unmanaged or without oversight for authorization. Maintenance of privileges using roles defined for discrete job functions offers improved oversight of application user privilege assignments and helps to protect against unauthorized privilege assignment.'
  desc 'check', "Check for direct user assignment to server permissions by running the following script:
/**********************************************************************************
 LIST ALL DIRECT SERVER PERMISSIONS TO ANY ACCOUNT EXCEPT
  SYSTEM ADMINISTRATOR accounts.  DO NOT LIST ROLES.
***********************************************************************************/
DECLARE @admin_Account_name sysname
SET @admin_Account_name = 'NO administrator account found'
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
   AND NOT pe.permission_name = 'connect sql'
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
   AND NOT pe.permission_name = 'connect sql'
 ORDER BY CASE pe.state
             WHEN 'D' THEN 1
             WHEN 'W' THEN 2
             WHEN 'G' THEN 3
             ELSE 4
          END

If any listed user-defined roles are not found in the system documentation, this is a finding.

Obtain the list of assigned privileges for all user-defined roles in the system documentation.

Check all SQL Server user-defined server roles for access rights as it relates to the separation of duties. Repeat steps for each user-defined server role.
Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Server Roles >> right click <'user-defined server role name'> >> Properties >> General >> Securables.  If any roles are found that do not enforce separation of duties, this is a finding."
  desc 'fix', "Add the user-defined server role to the system documentation.

Add the assigned privileges of the user-defined server role to the system documentation.

Remove the user from direct access to server permission by running the following script:
USE master
REVOKE <'server permission name'> TO <'account name'> CASCADE

Remove server role permission from the user-defined server role by running the following script:
USE master
REVOKE <'server role name'> TO [<'server role name'>]"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47792r7_chk'
  tag severity: 'medium'
  tag gid: 'V-41202'
  tag rid: 'SV-53669r4_rule'
  tag stig_id: 'SQL2-00-008800'
  tag gtitle: 'SRG-APP-000062-DB-000009'
  tag fix_id: 'F-46594r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002220']
  tag nist: ['CM-6 b', 'AC-5 b']
end
