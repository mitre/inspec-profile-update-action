control 'SV-255350' do
  title 'Azure SQL DB must be able to generate audit records when security objects are accessed.'
  desc 'Changes to the security configuration must be tracked. 

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 

In an SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced when security objects are accessed.

To determine if an audit is configured, execute the following script. 
Run this TSQL command to determine if SQL Auditing AuditActionGroups are configured:
  SELECT DISTINCT sd.audit_action_name 
  FROM sys.database_audit_specification_details sd
  JOIN sys.database_audit_specifications s 
  ON s.database_specification_id = sd.database_specification_id
  WHERE (name = 'SqlDbAuditing_ServerAuditSpec' /*Server Audit*/
      OR name = 'SqlDbAuditing_AuditSpec') /*Database Audit*/
  AND s.is_state_enabled = 1
  ORDER BY sd.audit_action_name

If no values exist for AuditActionGroup, this is a finding. 

Verify the following AuditActionGroup(s) are configured:
SCHEMA_OBJECT_ACCESS_GROUP

If any listed AuditActionGroups do not exist in the configuration, this is a finding."
  desc 'fix', 'Deploy an audit to review the retrieval of privilege/permission/role membership information. 
Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59023r871174_chk'
  tag severity: 'medium'
  tag gid: 'V-255350'
  tag rid: 'SV-255350r879863_rule'
  tag stig_id: 'ASQL-00-012900'
  tag gtitle: 'SRG-APP-000492-DB-000332'
  tag fix_id: 'F-58967r871175_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
