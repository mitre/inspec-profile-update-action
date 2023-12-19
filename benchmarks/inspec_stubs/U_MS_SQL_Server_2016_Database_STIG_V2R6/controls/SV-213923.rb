control 'SV-213923' do
  title 'SQL Server must prohibit user installation of logic modules (stored procedures, functions, triggers, views, etc.) without explicit privileged status.'
  desc 'Allowing regular users to install software, without explicit privileges, creates the risk that untested or potentially malicious software will be installed on the system. Explicit privileges (escalated or administrative privileges) provide the regular user with explicit capabilities and control that exceed the rights of a regular user.

DBMS functionality and the nature and requirements of databases will vary; so while users are not permitted to install unapproved software, there may be instances where the organization allows the user to install approved software packages such as from an approved software repository. The requirements for production servers will be more restrictive than those used for development and research.

SQL Server must enforce software installation by users based upon what types of software installations are permitted (e.g., updates and security patches to existing software) and what types of installations are prohibited (e.g., software whose pedigree with regard to being potentially malicious is unknown or suspect) by the organization). 

In the case of a database management system, this requirement covers stored procedures, functions, triggers, views, etc.'
  desc 'check', "If the SQL Server instance supports only software development, experimentation, and/or developer-level testing (that is, excluding production systems, integration testing, stress testing, and user acceptance testing), this is not a finding. 

Obtain a listing of users and roles who are authorized to create, alter, or replace logic modules from the server documentation.

In each user database, execute the following query:

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

SELECT R.name AS role_name, M.type_desc AS principal_type, M.name AS principal_name
FROM sys.database_principals R
JOIN sys.database_role_members DRM ON R.principal_id = DRM.role_principal_id
JOIN sys.database_principals M ON DRM.member_principal_id = M.principal_id
WHERE R.name IN ('db_ddladmin','db_owner')
AND M.name != 'dbo'

If any users or role permissions returned are not authorized to modify the specified object or type, this is a finding. 

If any user or role membership is not authorized, this is a finding."
  desc 'fix', 'Document and obtain approval for any non-administrative users who require the ability to create, alter, or replace logic modules.

Revoke the ALTER permission from unauthorized users and roles:
REVOKE ALTER ON [<Object Name>] TO [<Principal Name>]'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15141r799958_chk'
  tag severity: 'medium'
  tag gid: 'V-213923'
  tag rid: 'SV-213923r879751_rule'
  tag stig_id: 'SQL6-D0-003000'
  tag gtitle: 'SRG-APP-000378-DB-000365'
  tag fix_id: 'F-15139r313202_fix'
  tag 'documentable'
  tag legacy: ['SV-93815', 'V-79109']
  tag cci: ['CCI-001812']
  tag nist: ['CM-11 (2)']
end
