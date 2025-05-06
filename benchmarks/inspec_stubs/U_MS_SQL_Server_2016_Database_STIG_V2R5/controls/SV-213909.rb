control 'SV-213909' do
  title 'The role(s)/group(s) used to modify database structure (including but not necessarily limited to tables, indexes, storage, etc.) and logic modules (stored procedures, functions, triggers, links to software external to SQL Server, etc.) must be restricted to authorized users.'
  desc 'If SQL Server were to allow any user to make changes to database structure or logic, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

Accordingly, only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.

Unmanaged changes that occur to the database software libraries or configuration can lead to unauthorized or compromised installations.'
  desc 'check', "Obtain a listing of users and roles who are authorized to modify database structure and logic modules from the server documentation.

Execute the following query:
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
  desc 'fix', 'Document and obtain approval for any non-administrative users who require the ability to modify database structure and logic modules.

REVOKE ALTER ON [<Object Name>] TO [<Principal Name>]'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Database'
  tag check_id: 'C-15127r313159_chk'
  tag severity: 'medium'
  tag gid: 'V-213909'
  tag rid: 'SV-213909r508025_rule'
  tag stig_id: 'SQL6-D0-001400'
  tag gtitle: 'SRG-APP-000133-DB-000362'
  tag fix_id: 'F-15125r313160_fix'
  tag 'documentable'
  tag legacy: ['SV-93787', 'V-79081']
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
