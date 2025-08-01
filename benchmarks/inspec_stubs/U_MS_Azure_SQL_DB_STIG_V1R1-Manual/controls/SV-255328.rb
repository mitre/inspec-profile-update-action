control 'SV-255328' do
  title 'Azure SQL Database must initiate session auditing upon startup.'
  desc "Session auditing is for use when a user's activities are under investigation. To ensure capture of all activity during those periods when session auditing is in use, it needs to be in operation for the whole time Azure SQL Database is running."
  desc 'check', "When Audits are enabled, they start up when the audits are enabled and remain operating until the audit is disabled. 

Check if an audit is configured and enabled. 
To determine if session auditing is configured and enabled, follow the instructions below: 
Run this TSQL command to determine if SQL Auditing is configured and enabled:
   SELECT *
   FROM sys.database_audit_specifications
   where (name = 'SqlDbAuditing_ServerAuditSpec' 
       or name = 'SqlDbAuditing_AuditSpec')
   and is_state_enabled = 1

All currently defined audits for the Azure SQL Database instance will be listed. If no audits are returned, this is a finding."
  desc 'fix', 'Deploy an Azure SQL Database audit.

Refer to the supplemental file "AzureSQLDatabaseAudit.txt" PowerShell script.

Reference: 
https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59001r871108_chk'
  tag severity: 'medium'
  tag gid: 'V-255328'
  tag rid: 'SV-255328r877243_rule'
  tag stig_id: 'ASQL-00-004700'
  tag gtitle: 'SRG-APP-000092-DB-000208'
  tag fix_id: 'F-58945r877242_fix'
  tag 'documentable'
  tag cci: ['CCI-001464']
  tag nist: ['AU-14 (1)']
end
