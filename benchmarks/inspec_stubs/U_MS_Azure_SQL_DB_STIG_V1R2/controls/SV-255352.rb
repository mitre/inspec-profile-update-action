control 'SV-255352' do
  title 'Azure SQL DB must generate audit records when categorized information (e.g., classification levels/security levels) is accessed.'
  desc 'Changes in categorized information must be tracked. Without an audit trail, unauthorized access to protected data could go undetected. 

For detailed information on categorizing information, refer to FIPS Publication 199, Standards for Security Categorization of Federal Information and Information Systems, and FIPS Publication 200, Minimum Security Requirements for Federal Information and Information Systems.'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced when categorized information is accessed.

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
  tag check_id: 'C-59025r871180_chk'
  tag severity: 'medium'
  tag gid: 'V-255352'
  tag rid: 'SV-255352r879865_rule'
  tag stig_id: 'ASQL-00-013100'
  tag gtitle: 'SRG-APP-000494-DB-000344'
  tag fix_id: 'F-58969r871181_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
