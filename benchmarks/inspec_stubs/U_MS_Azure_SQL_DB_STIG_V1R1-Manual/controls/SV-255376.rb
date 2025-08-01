control 'SV-255376' do
  title 'Azure SQL Database must generate audit records for all direct access to the database(s).'
  desc 'In this context, direct access is any query, command, or call to Azure SQL Database that comes from any source other than the application(s) that it supports. Examples would be the command line or a database management utility program. The intent is to capture all activity from administrative and nonstandard sources.'
  desc 'check', 'Review Azure SQL Database configuration to verify that audit records are produced for all direct access to the database(s).

To determine if an audit PredicateExpression (filter) exists, execute the following PowerShell script. 
1. In the Azure Portal, open a Cloud Shell session.
2. Run this PowerShell command to determine the PredicateExpression:

$ResourceGroup = "myResourceGroup"
$ServerName = "myServerName"
$FormatEnumerationLimit=-1
Get-AzSqlServerAudit -ResourceGroupName $ResourceGroup -ServerName $ServerName

If a PredicateExpression is returned, review the associated filters to determine whether administrative activities are being excluded. 

If any audits are configured to exclude administrative activities, this is a finding.'
  desc 'fix', 'Check the system documentation for required Azure SQL Database Audits. Remove any Audit filters that exclude or reduce required auditing. Update filters to ensure administrative activity is not excluded.'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59049r871252_chk'
  tag severity: 'medium'
  tag gid: 'V-255376'
  tag rid: 'SV-255376r871254_rule'
  tag stig_id: 'ASQL-00-015500'
  tag gtitle: 'SRG-APP-000508-DB-000358'
  tag fix_id: 'F-58993r871253_fix'
  tag 'documentable'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']
end
