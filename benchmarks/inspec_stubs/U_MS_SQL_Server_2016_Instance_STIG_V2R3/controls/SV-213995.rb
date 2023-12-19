control 'SV-213995' do
  title 'SQL Server must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked. 
 
This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 
 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE'
  desc 'check', %q(Determine if an audit is configured and started by executing the following query.  

SELECT name AS 'Audit Name', 
status_desc AS 'Audit Status', 
audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status

If no records are returned, this is a finding. 

If the auditing the retrieval of privilege/permission/role membership information is required, execute the following query to verify the SCHEMA_OBJECT_ACCESS_GROUP is included in the server audit specification. 

SELECT a.name AS 'AuditName', 
s.name AS 'SpecName', 
d.audit_action_name AS 'ActionName', 
d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 

If the "SCHEMA_OBJECT_ACCESS_GROUP" is not returned in an active audit, this is a finding.)
  desc 'fix', 'Deploy an audit to audit the retrieval of privilege/permission/role membership information. See the supplemental file "SQL 2016 Audit.sql".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15212r313768_chk'
  tag severity: 'medium'
  tag gid: 'V-213995'
  tag rid: 'SV-213995r617437_rule'
  tag stig_id: 'SQL6-D0-012900'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-15210r313769_fix'
  tag 'documentable'
  tag legacy: ['SV-93957', 'V-79251']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
