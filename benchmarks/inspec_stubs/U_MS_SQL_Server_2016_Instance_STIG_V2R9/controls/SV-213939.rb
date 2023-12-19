control 'SV-213939' do
  title 'SQL Server must generate audit records when successful/unsuccessful attempts to retrieve privileges/permissions occur.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, monitoring must be possible. DBMSs typically make such information available through views or functions.
 
This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted. 
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

'
  desc 'check', "Review the system documentation to determine if SQL Server is required to audit the retrieval of privilege/permission/role membership information. 
 
If SQL Server is not required to audit the retrieval of privilege/permission/role membership information, this is not a finding. 
 
If the documentation does not exist, this is a finding. 
 
Determine if an audit is configured and started by executing the following query. If no records are returned, this is a finding. 
 
SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
If the auditing the retrieval of privilege/permission/role membership information is required, execute the following query to verify the SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification. 
 
SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
 
If the SCHEMA_OBJECT_ACCESS_GROUP is not returned in an active audit, this is a finding."
  desc 'fix', 'Deploy an audit to audit the retrieval of privilege/permission/role membership information. See the supplemental file "SQL 2016 Audit.sql".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15156r313600_chk'
  tag severity: 'medium'
  tag gid: 'V-213939'
  tag rid: 'SV-213939r902984_rule'
  tag stig_id: 'SQL6-D0-004600'
  tag gtitle: 'SRG-APP-000091-DB-000325'
  tag fix_id: 'F-15154r313601_fix'
  tag satisfies: ['SRG-APP-000091-DB-000066']
  tag 'documentable'
  tag legacy: ['SV-93845', 'V-79139']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
