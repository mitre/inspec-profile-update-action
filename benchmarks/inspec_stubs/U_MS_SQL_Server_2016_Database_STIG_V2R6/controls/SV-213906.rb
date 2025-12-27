control 'SV-213906' do
  title 'SQL Server must limit privileges to change software modules, to include stored procedures, functions, and triggers.'
  desc 'If the system were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "Obtain a listing of users and roles who are authorized to change stored procedures, functions, and triggers from the server documentation.

In each user database, execute the following query:

SELECT P.type_desc AS principal_type, P.name AS principal_name, O.type_desc,
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
  desc 'fix', 'Revoke the ALTER permission from unauthorized users and roles.

REVOKE ALTER ON [<Object Name>] TO [<Principal Name>]'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15124r810828_chk'
  tag severity: 'medium'
  tag gid: 'V-213906'
  tag rid: 'SV-213906r879586_rule'
  tag stig_id: 'SQL6-D0-001100'
  tag gtitle: 'SRG-APP-000133-DB-000179'
  tag fix_id: 'F-15122r313151_fix'
  tag 'documentable'
  tag legacy: ['SV-93781', 'V-79075']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
