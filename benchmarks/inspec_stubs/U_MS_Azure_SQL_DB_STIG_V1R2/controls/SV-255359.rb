control 'SV-255359' do
  title 'Azure SQL DB must generate audit records when unsuccessful attempts to modify security objects occur.'
  desc 'Changes in the database objects (tables, views, procedures, functions) that record and control permissions, privileges, and roles granted to users and roles must be tracked. Without an audit trail, unauthorized changes to the security subsystem could go undetected. The database could be severely compromised or rendered inoperative. 

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced when unsuccessful attempts to modify security objects occur.

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
SCHEMA_OBJECT_CHANGE_GROUP

If any listed AuditActionGroups do not exist in the configuration, this is a finding."
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.

Reference: 
https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit">https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59032r871201_chk'
  tag severity: 'medium'
  tag gid: 'V-255359'
  tag rid: 'SV-255359r879867_rule'
  tag stig_id: 'ASQL-00-013800'
  tag gtitle: 'SRG-APP-000496-DB-000335'
  tag fix_id: 'F-58976r871202_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
