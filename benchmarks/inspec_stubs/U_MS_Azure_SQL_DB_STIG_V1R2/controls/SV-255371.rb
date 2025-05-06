control 'SV-255371' do
  title 'Azure SQL Database must generate audit records for all unsuccessful attempts to execute privileged activities or other system-level access.'
  desc 'Without tracking privileged activity, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one. 

System documentation should include a definition of the functionality considered privileged.

A privileged function in this context is any operation that modifies the structure of the database, its built-in logic, or its security settings. This would include all Data Definition Language (DDL) statements and all security-related statements. In an SQL environment, it encompasses, but is not necessarily limited to:
CREATE
ALTER
DROP
GRANT
REVOKE
DENY

Note that it is particularly important to audit, and tightly control, any action that weakens the implementation of this requirement itself, since the objective is to have a complete audit trail of all administrative activity.

To aid in diagnosis, it is necessary to keep track of failed attempts in addition to the successful ones.'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced for all unsuccessful attempts to execute privileged activities or other system-level access.

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
APPLICATION_ROLE_CHANGE_PASSWORD_GROUP 
BACKUP_RESTORE_GROUP 
DATABASE_CHANGE_GROUP
DATABASE_OBJECT_CHANGE_GROUP 
DATABASE_OBJECT_OWNERSHIP_CHANGE_GROUP 
DATABASE_OBJECT_PERMISSION_CHANGE_GROUP 
DATABASE_OPERATION_GROUP 
DATABASE_OWNERSHIP_CHANGE_GROUP 
DATABASE_PERMISSION_CHANGE_GROUP
DATABASE_PRINCIPAL_CHANGE_GROUP 
DATABASE_PRINCIPAL_IMPERSONATION_GROUP 
DATABASE_ROLE_MEMBER_CHANGE_GROUP 
DBCC_GROUP 
SCHEMA_OBJECT_CHANGE_GROUP 
SCHEMA_OBJECT_OWNERSHIP_CHANGE_GROUP 
SCHEMA_OBJECT_PERMISSION_CHANGE_GROUP 
USER_CHANGE_PASSWORD_GROUP

If any listed AuditActionGroups do not exist in the configuration, this is a finding."
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.

Reference: 
https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit">https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59044r871237_chk'
  tag severity: 'medium'
  tag gid: 'V-255371'
  tag rid: 'SV-255371r879875_rule'
  tag stig_id: 'ASQL-00-015000'
  tag gtitle: 'SRG-APP-000504-DB-000355'
  tag fix_id: 'F-58988r871238_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
