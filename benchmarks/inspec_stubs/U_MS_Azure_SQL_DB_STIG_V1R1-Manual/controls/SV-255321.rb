control 'SV-255321' do
  title 'Azure SQL Database must implement cryptographic mechanisms to prevent unauthorized modification of organization-defined information at rest (to include, at a minimum, PII and classified information) on organization-defined information system components.'
  desc 'Azure SQL Databases handling data requiring "data at rest" protections must employ cryptographic mechanisms to prevent unauthorized disclosure and modification of the information at rest.

Selection of a cryptographic mechanism is based on the need to protect the integrity of organizational information. The strength of the mechanism is commensurate with the security category and/or classification of the information. 

The decision whether and what to encrypt rests with the data owner and is also influenced by the physical measures taken to secure the equipment and media on which the information resides.'
  desc 'check', 'Review the system documentation to determine whether the organization has defined the information at rest that is to be protected from modification, which must include, at a minimum, PII and classified information. 

If no information is identified as requiring such protection, this is not a finding. 

Review the configuration of the Azure SQL Database to ensure data at rest protections are implemented. 

If any of the information defined as requiring cryptographic protection from modification is not encrypted in a manner that provides the required level of protection, this is a finding. 

Retrieve Transparent Data Encryption status: 

$LogicalServerName = "myServer" 
$RGname = "myRG" 
$DBName = "myDatabase" 
Get-AzSqlDatabaseTransparentDataEncryption -ServerName $LogicalServerName -ResourceGroupName $RGname -DatabaseName $DBname 

Validate that Azure SQL Database Transparent Data Encryption (TDE) is enabled. If TDE is disabled, this is a finding.'
  desc 'fix', 'If Azure SQL Database Transparent Data Encryption is disabled, use the Set-AzSqlDatabaseTransparentDataEncryption command to enable. 

$LogicalServerName = "myServer" 
$RGname = "myRG" 
$DBname = "myDatabase" 
$TDEstate = "Enabled" 

Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $RGname -ServerName $LogicalServerName -DatabaseName $DBname -State $TDEstate'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-58994r871087_chk'
  tag severity: 'medium'
  tag gid: 'V-255321'
  tag rid: 'SV-255321r871089_rule'
  tag stig_id: 'ASQL-00-003300'
  tag gtitle: 'SRG-APP-000428-DB-000386'
  tag fix_id: 'F-58938r871088_fix'
  tag 'documentable'
  tag cci: ['CCI-002475']
  tag nist: ['SC-28 (1)']
end
