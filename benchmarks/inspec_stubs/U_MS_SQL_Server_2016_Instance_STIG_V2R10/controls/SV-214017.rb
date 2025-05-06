control 'SV-214017' do
  title 'SQL Server must generate audit records showing starting and ending time for user access to the database(s).'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to SQL Server lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs.  
 
Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  desc 'check', "Determine if an audit is configured and started by executing the following query:  

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 

If no records are returned, this is a finding. 

Execute the following query to verify the following events are included in the server audit specification: 

APPLICATION_ROLE_CHANGE_PASSWORD_GROUP 
AUDIT_CHANGE_GROUP 
BACKUP_RESTORE_GROUP 
DATABASE_CHANGE_GROUP 
DATABASE_OBJECT_CHANGE_GROUP 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OPERATION_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP 
DATABASE_PRINCIPAL_CHANGE_GROUP 
DATABASE_PRINCIPAL_IMPERSONATION_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
DBCC_GROUP 
LOGIN_CHANGE_PASSWORD_GROUP
LOGOUT_GROUP 
SCHEMA_OBJECT_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OBJECT_CHANGE_GROUP 
SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP 
SERVER_OBJECT_PERMISSION_CHANGE_GROUP 
SERVER_OPERATION_GROUP 
SERVER_PERMISSION_CHANGE_GROUP 
SERVER_PRINCIPAL_CHANGE_GROUP 
SERVER_PRINCIPAL_IMPERSONATION_GROUP 
SERVER_ROLE_MEMBER_CHANGE_GROUP 
SERVER_STATE_CHANGE_GROUP 
TRACE_CHANGE_GROUP 
USER_CHANGE_PASSWORD_GROUP 

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1  
AND d.audit_action_name IN ('APPLICATION_ROLE_CHANGE_PASSWORD_GROUP',
'AUDIT_CHANGE_GROUP',
'BACKUP_RESTORE_GROUP',
'DATABASE_CHANGE_GROUP',
'DATABASE_OBJECT_CHANGE_GROUP',
'DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP',
'DATABASE_OBJECT_PERMISSION_CHANGE_GROUP',
'DATABASE_OPERATION_GROUP',
'DATABASE_OWNERSHIP_CHANGE_GROUP',
'DATABASE_PERMISSION_CHANGE_GROUP',
'DATABASE_PRINCIPAL_CHANGE_GROUP',
'DATABASE_PRINCIPAL_IMPERSONATION_GROUP',
'DATABASE_ROLE_MEMBER_CHANGE_GROUP',
'DBCC_GROUP',
'LOGIN_CHANGE_PASSWORD_GROUP',
'LOGOUT_GROUP',
'SCHEMA_OBJECT_CHANGE_GROUP',
'SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OBJECT_CHANGE_GROUP',
'SERVER_OBJECT_OWNERSHIP_CHANGE_GROUP',
'SERVER_OBJECT_PERMISSION_CHANGE_GROUP',
'SERVER_OPERATION_GROUP',
'SERVER_PERMISSION_CHANGE_GROUP',
'SERVER_PRINCIPAL_CHANGE_GROUP',
'SERVER_PRINCIPAL_IMPERSONATION_GROUP',
'SERVER_ROLE_MEMBER_CHANGE_GROUP',
'SERVER_STATE_CHANGE_GROUP',
'TRACE_CHANGE_GROUP',
'USER_CHANGE_PASSWORD_GROUP'
)
Order by d.audit_action_name


If the identified groups are not returned, this is a finding."
  desc 'fix', 'Add the "LOGOUT_GROUP" to the server audit specification 
USE [master]; 
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (LOGOUT_GROUP);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15234r313834_chk'
  tag severity: 'medium'
  tag gid: 'V-214017'
  tag rid: 'SV-214017r879876_rule'
  tag stig_id: 'SQL6-D0-015100'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-15232r313835_fix'
  tag 'documentable'
  tag legacy: ['SV-94001', 'V-79295']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
