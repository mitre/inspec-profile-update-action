control 'SV-214020' do
  title 'SQL Server must generate audit records when successful and unsuccessful accesses to objects occur.'
  desc 'Without tracking all or selected types of access to all or selected objects (tables, views, procedures, functions, etc.), it would be difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one.  
 
In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE 
 
To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.

'
  desc 'check', %q(Review the system documentation to determine if SQL Server is required to audit when successful and unsuccessful accesses to objects occur. 
 
If this is not required, this is not a finding. 
 
If the documentation does not exist, this is a finding. 
 
Determine if an audit is configured and started by executing the following query:  
 
SELECT name AS 'Audit Name', 
  status_desc AS 'Audit Status', 
  audit_file_path AS 'Current Audit File' 
FROM sys.dm_server_audit_status 
 
If no records are returned, this is a finding. 
 
If the auditing the retrieval of privilege/permission/role membership information is required, execute the following query to verify the "SCHEMA_OBJECT_ACCESS_GROUP" is included in the server audit specification. 
 
SELECT a.name AS 'AuditName', 
 s.name AS 'SpecName', 
 d.audit_action_name AS 'ActionName', 
 d.audited_result AS 'Result' 
FROM sys.server_audit_specifications s 
JOIN sys.server_audits a ON s.audit_guid = a.audit_guid 
JOIN sys.server_audit_specification_details d ON s.server_specification_id = d.server_specification_id 
WHERE a.is_state_enabled = 1 AND d.audit_action_name = 'SCHEMA_OBJECT_ACCESS_GROUP' 
 
If the "SCHEMA_OBJECT_ACCESS_GROUP" is not returned in an active audit, this is a finding.)
  desc 'fix', 'Deploy an audit to audit when successful and unsuccessful accesses to objects occur. See the supplemental file "SQL 2016 Audit.sql".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15237r903004_chk'
  tag severity: 'medium'
  tag gid: 'V-214020'
  tag rid: 'SV-214020r903006_rule'
  tag stig_id: 'SQL6-D0-015400'
  tag gtitle: 'SRG-APP-000507-DB-000357'
  tag fix_id: 'F-15235r903005_fix'
  tag satisfies: ['SRG-APP-000507-DB-000356']
  tag 'documentable'
  tag legacy: ['SV-94007', 'V-79301']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
