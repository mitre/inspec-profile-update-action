control 'SV-214014' do
  title 'SQL Server must generate audit records when successful and unsuccessful logons or connection attempts occur.'
  desc 'For completeness of forensic analysis, it is necessary to track who/what (a user or other principal) logs on to SQL Server. It is also necessary to track failed attempts to log on to SQL Server. While positive identification may not be possible in a case of failed authentication, as much information as possible about the incident must be captured.

'
  desc 'check', %q(Determine if an audit is configured and started by executing the following query: 
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
Execute the following query to verify the SUCCESSFUL_LOGIN_GROUP and FAILED_LOGIN_GROUP are included in the server audit specification.
 
SELECT a.name AS 'AuditName', 
  s.name AS 'SpecName', 
 d.audit_action_name AS 'ActionName', 
  d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name IN ('SUCCESSFUL_LOGIN_GROUP', 'FAILED_LOGIN_GROUP') 

If both "SUCCESSFUL_LOGIN_GROUP" and "FAILED_LOGIN_GROUP" are returned in an active audit, this is not a finding.
 
If both "SUCCESSFUL_LOGIN_GROUP" and "FAILED_LOGIN_GROUP" are not in the active audit, determine whether "Both failed and successful logins" is enabled.
 
In SQL Management Studio 
Right-click on the instance 
>> Select "Properties" 
>> Select "Security" on the left hand side 
>> Check the setting for "Login auditing" 
 
If "Both failed and successful logins" is not selected, this is a finding.)
  desc 'fix', 'Add both "SUCCESSFUL_LOGIN_GROUP" and "FAILED_LOGIN_GROUP" to the server audit specification. 
USE [master];
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = OFF);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (SUCCESSFUL_LOGIN_GROUP);  
GO  

ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION ADD (FAILED_LOGIN_GROUP);  
GO  
 
ALTER SERVER AUDIT SPECIFICATION STIG_AUDIT_SERVER_SPECIFICATION WITH (STATE = ON);  
GO 
 
Alternatively, enable "Both failed and successful logins".

In SQL Management Studio:
Right-click on the instance.
- Select "Properties".
- Select "Security" on the left-hand side.
- Select "Both failed and successful logins". 
- Click "OK".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15231r903001_chk'
  tag severity: 'medium'
  tag gid: 'V-214014'
  tag rid: 'SV-214014r903003_rule'
  tag stig_id: 'SQL6-D0-014800'
  tag gtitle: 'SRG-APP-000503-DB-000351'
  tag fix_id: 'F-15229r903002_fix'
  tag satisfies: ['SRG-APP-000503-DB-000350']
  tag 'documentable'
  tag legacy: ['SV-93995', 'V-79289']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
