control 'SV-255326' do
  title 'The Azure SQL Database must be able to generate audit records when privileges/permissions are retrieved.'
  desc 'Under some circumstances, it may be useful to monitor who/what is reading privilege/permission/role information. Therefore, it must be possible to configure auditing to do this. DBMSs typically make such information available through views or functions. 

This requirement addresses explicit requests for privilege/permission/role membership information. It does not refer to the implicit retrieval of privileges/permissions/role memberships that SQL Server continually performs to determine if any and every action on the database is permitted.'
  desc 'check', "Review Azure SQL Database configuration to verify that audit records are produced when privileges/permissions/role memberships are retrieved. 

To determine if an audit is configured, follow the instructions below: 
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
  tag check_id: 'C-58999r871102_chk'
  tag severity: 'medium'
  tag gid: 'V-255326'
  tag rid: 'SV-255326r877251_rule'
  tag stig_id: 'ASQL-00-004500'
  tag gtitle: 'SRG-APP-000091-DB-000066'
  tag fix_id: 'F-58943r877250_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
