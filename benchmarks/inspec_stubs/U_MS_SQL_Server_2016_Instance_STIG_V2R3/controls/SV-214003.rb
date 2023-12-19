control 'SV-214003' do
  title 'SQL Server must generate audit records when security objects are modified.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative.'
  desc 'check', %q(Determine if an audit is configured and started by executing the following query: 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
If no records are returned, this is a finding. 
 
Execute the following query to verify the "SCHEMA_OBJECT_CHANGE_GROUP" is included in the server audit specification. 
 
SELECT a.name AS 'AuditName', 
  s.name AS 'SpecName', 
  d.audit_action_name AS 'ActionName', 
  d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_CHANGE_GROUP' 
 
If the "SCHEMA_OBJECT_CHANGE_GROUP" is not returned in an active audit, this is a finding.)
  desc 'fix', 'Add the "SCHEMA_OBJECT_CHANGE_GROUP" to the server audit specification 
USE [master]; 
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SCHEMA_OBJECT_CHANGE_GROUP);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15220r313792_chk'
  tag severity: 'medium'
  tag gid: 'V-214003'
  tag rid: 'SV-214003r617437_rule'
  tag stig_id: 'SQL6-D0-013700'
  tag gtitle: 'SRG-APP-000496-DB-000334'
  tag fix_id: 'F-15218r313793_fix'
  tag 'documentable'
  tag legacy: ['SV-93973', 'V-79267']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
