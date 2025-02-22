control 'SV-214013' do
  title 'SQL Server must generate audit records when successful logons or connections occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to SQL Server.'
  desc 'check', %q(Determine if an audit is configured and started by executing the following query. 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
Execute the following query to verify the SUCCESSFUL_LOGIN_GROUP is included in the server audit specification. 
 
SELECT a.name AS 'AuditName', 
  s.name AS 'SpecName', 
 d.audit_action_name AS 'ActionName', 
  d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SUCCESSFUL_LOGIN_GROUP' 
 
If the "SUCCESSFUL_LOGIN_GROUP" is returned in an active audit, this is not a finding. 
 
If "SUCCESSFUL_LOGIN_GROUP" is not in the active audit, determine whether "Both failed and successful logins" is enabled. 
 
In SQL Management Studio 
Right-click on the instance 
>> Select "Properties" 
>> Select "Security" on the left hand side 
>> Check the setting for "Login auditing" 
 
If "Both failed and successful logins" is not selected, this is a finding.)
  desc 'fix', 'Add the "SUCCESSFUL_LOGIN_GROUP" to the server audit specification. 
USE [master]; 
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SUCCESSFUL_LOGIN_GROUP);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO 
 
Alternatively, enable "Both failed and successful logins" 
In SQL Management Studio 
Right-click on the instance 
>> Select "Properties" 
>> Select "Security" on the left hand side 
>> Select "Both failed and successful logins" 
>> Click "OK"'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15230r313822_chk'
  tag severity: 'medium'
  tag gid: 'V-214013'
  tag rid: 'SV-214013r617437_rule'
  tag stig_id: 'SQL6-D0-014700'
  tag gtitle: 'SRG-APP-000503-DB-000350'
  tag fix_id: 'F-15228r313823_fix'
  tag 'documentable'
  tag legacy: ['SV-93993', 'V-79287']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
