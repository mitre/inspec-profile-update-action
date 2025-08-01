control 'SV-255351' do
  title 'Azure SQL DB must generate audit records when unsuccessful attempts to access security objects occur.'
  desc 'Changes to the security configuration must be tracked. 

This requirement applies to situations where security data is retrieved or modified via data manipulation operations, as opposed to via specialized security functionality. 

In a SQL environment, types of access include, but are not necessarily limited to: 
SELECT 
INSERT 
UPDATE 
DELETE 
EXECUTE'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced when unsuccessful attempts to access security objects occur.

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
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.

Reference: 
https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit">https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59024r877257_chk'
  tag severity: 'medium'
  tag gid: 'V-255351'
  tag rid: 'SV-255351r879863_rule'
  tag stig_id: 'ASQL-00-013000'
  tag gtitle: 'SRG-APP-000492-DB-000333'
  tag fix_id: 'F-58968r877225_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
