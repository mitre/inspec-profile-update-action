control 'SV-255322' do
  title 'Azure SQL Database must implement cryptographic mechanisms preventing the unauthorized disclosure of organization-defined information at rest on organization-defined information system components.'
  desc 'Azure SQL Databases handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest. 

 Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information. 

If no information is identified as requiring such protection, this is not a finding. 

Review the configuration of the Azure SQL Database to ensure data at rest protections are implemented. 

If any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding. 

Retrieve Transparent Data Encryption status: 
$LogicalServerName = "myServerName" 
$RGname = "myResourceGroup" 
$DBName = "myDatabaseName" 

Get-AzSqlDatabaseTransparentDataEncryption -ServerName $LogicalServerName -ResourceGroupName $RGname -DatabaseName $DBname'
  desc 'fix', 'If Azure SQL Database Transparent Data Encryption is disabled, use the Set-AzSqlDatabaseTransparentDataEncryption command to enable. 

$LogicalServerName = "myServerName" 
$RGname = "myResourceGroup" 
$DBName = "myDatabaseName" 

$TDEstate = "Enabled" 

Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $RGname -ServerName $LogicalServerName -DatabaseName $DBname -State $TDEstate'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58995r871090_chk'
  tag severity: 'medium'
  tag gid: 'V-255322'
  tag rid: 'SV-255322r879800_rule'
  tag stig_id: 'ASQL-00-003400'
  tag gtitle: 'SRG-APP-000429-DB-000387'
  tag fix_id: 'F-58939r871091_fix'
  tag 'documentable'
  tag cci: ['CCI-002476']
  tag nist: ['SC-28 (1)']
end
