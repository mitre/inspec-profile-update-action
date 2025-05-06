control 'SV-214005' do
  title 'SQL Server must generate audit records when categorized information (e.g., classification levels/security levels) is modified.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 
 
For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', %q(Review the system documentation to determine if SQL Server is required to audit when data classifications are modified. 
 
If this is not required, this is not a finding. 
 
If the documentation does not exist, this is a finding. 
 
Determine if an audit is configured and started by executing the following query.  
 
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
  desc 'fix', 'Deploy an audit to audit when data classifications are modified. See the supplemental file "SQL 2016 Audit.sql".'
  impact 0.5
  ref 'DPMS Target MS SQL Server 2016 Instance'
  tag check_id: 'C-15222r313798_chk'
  tag severity: 'medium'
  tag gid: 'V-214005'
  tag rid: 'SV-214005r617437_rule'
  tag stig_id: 'SQL6-D0-013900'
  tag gtitle: 'SRG-APP-000498-DB-000346'
  tag fix_id: 'F-15220r313799_fix'
  tag 'documentable'
  tag legacy: ['SV-93977', 'V-79271']
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
