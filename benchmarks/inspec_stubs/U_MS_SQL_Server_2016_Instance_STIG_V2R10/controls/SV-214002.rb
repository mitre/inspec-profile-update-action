control 'SV-214002' do
  title 'SQL Server must generate audit records when successful and unsuccessful attempts to modify privileges/permissions occur.'
  desc 'Changes in the permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized elevation or restriction of privileges could go undetected. Elevated privileges give users access to information and functionality that they should not have; restricted privileges wrongly deny access to authorized users. 
 
In an SQL environment, modifying permissions is typically done via the GRANT, REVOKE, and DENY commands.  
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

'
  desc 'check', "Check that SQL Server Audit is being used for the STIG compliant audit.

Determine if an audit is configured and started by executing the following query:

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status

Execute the following query to verify the required audit actions are included in the server audit specification:

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1
AND d.audit_action_name IN ('DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP'
,'DATABASE_OWNERSHIP_CHANGE_GROUP'
,'DATABASE_PERMISSION_CHANGE_GROUP'
,'DATABASE_ROLE_MEMBER_CHANGE_GROUP'
,'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP'
,'SERVER_OBJECT_PERMISSION_CHANGE_GROUP'
,'SERVER_PERMISSION_CHANGE_GROUP'
,'SERVER_ROLE_MEMBER_CHANGE_GROUP')

If the any of the following audit actions are not returned in an active audit, this is a finding.

DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 

If no records are returned, this is a finding."
  desc 'fix', 'Add the following events to the SQL Server Audit that is being used for the STIG compliant audit. 
 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
 
See the supplemental file "SQL 2016 Audit.sql". 

Reference: 
https://msdn.microsoft.com/en-us/library/cc280663.aspx'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15219r902992_chk'
  tag severity: 'medium'
  tag gid: 'V-214002'
  tag rid: 'SV-214002r902993_rule'
  tag stig_id: 'SQL6-D0-013600'
  tag gtitle: 'SRG-APP-000495-DB-000329'
  tag fix_id: 'F-15217r313790_fix'
  tag satisfies: ['SRG-APP-000495-DB-000328']
  tag 'documentable'
  tag legacy: ['SV-93971', 'V-79265']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
