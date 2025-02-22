control 'SV-255372' do
  title 'Azure SQL Database must generate audit records when concurrent logons/connections by the same user from different workstations occur.'
  desc "For completeness of forensic analysis, it is necessary to know how long a user's (or other principal's) connection to the Azure Database lasts. This can be achieved by recording disconnections, in addition to logons/connections, in the audit logs. 

Disconnection may be initiated by the user or forced by the system (as in a timeout) or result from a system or network failure. To the greatest extent possible, all disconnections must be logged."
  desc 'check', 'Review Azure SQL Database configuration to verify that audit records are produced showing starting and ending time for user access to the database(s).

To determine if an audit is configured, execute the following script. 
Run this TSQL command to determine if SQL Auditing AuditActionGroups are configured:
   SELECT distinct audit_action_name
   FROM sys.database_audit_specification_details 
   ORDER BY audit_action_name

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

If any listed AuditActionGroups do not exist in the configuration, this is a finding.'
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.

Reference: 
https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit">https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59045r871240_chk'
  tag severity: 'medium'
  tag gid: 'V-255372'
  tag rid: 'SV-255372r879876_rule'
  tag stig_id: 'ASQL-00-015100'
  tag gtitle: 'SRG-APP-000505-DB-000352'
  tag fix_id: 'F-58989r871241_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
