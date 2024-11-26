control 'SV-53421' do
  title 'SQL Server must restrict access to sensitive information to authorized user roles.'
  desc 'Applications employ the concept of least privilege for specific duties and information systems (including specific functions, ports, protocols, and services). The concept of least privilege is also applied to information system processes, ensuring that the processes operate at privilege levels no higher than necessary to accomplish required organizational missions and/or functions. Organizations consider the creation of additional processes, roles, and information system accounts as necessary to achieve least privilege. Organizations also apply least privilege concepts to the design, development, implementation, and operations of information systems.

Unauthorized access to sensitive data may compromise the confidentiality of personnel privacy, threaten national security or compromise a variety of other sensitive operations. Access controls are best managed by defining requirements based on distinct job functions and assigning access based on the job function assigned to the individual user.'
  desc 'check', "Obtain the list of available user-defined server roles from system documentation.

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

Obtain the list assigned privileges for all user-defined roles in the system documentation.

Check all SQL Server user-defined server roles for access rights as it relates to the separation of duties. Repeat steps for each user-defined server role.
Navigate to SQL Server Management Studio >> Object Explorer >> <'SQL Server name'> >> Security >> Server Roles >> right click <'user-defined server role name'> >> Properties >> General >> Securables. If any user-defined role is assigned privileges that are not documented in the system documentation, this is a finding.

If any user-defined role contains permissions that are inconsistent with separation sensitive information assignment, this is a finding.

If system access requires more than one level of sensitive information access and the user-defined role names do not clearly differentiate between the different levels of sensitive information, this is a finding."
  desc 'fix', "Add the user-defined server role to the system documentation.

Add the assigned privileges of the user-defined server role to the system documentation.

Remove the user from direct access to server permission by running the following script:
USE master
REVOKE <'server permission name'> TO <'account name'> CASCADE

Remove server role permission from the user-defined server role by running the following script:
USE master
REVOKE <'server role name'> TO [<'server role name'>]

Rename the user-defined role by running the following script:
USE master
ALTER SERVER ROLE [<'old role name'>] WITH NAME = [<'new role name'>]"
  impact 0.5
  ref 'DPMS Target SQL Server Installation 2012'
  tag check_id: 'C-47663r2_chk'
  tag severity: 'medium'
  tag gid: 'V-41046'
  tag rid: 'SV-53421r2_rule'
  tag stig_id: 'SQL2-00-009000'
  tag gtitle: 'SRG-APP-000062-DB-000011'
  tag fix_id: 'F-46345r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-002220']
  tag nist: ['CM-6 b', 'AC-5 b']
end
