control 'SV-255339' do
  title 'Azure SQL Database must protect the confidentiality and integrity of all information at rest.'
  desc 'This control is intended to address the confidentiality and integrity of information at rest in nonmobile devices and covers user information and system information. Information at rest refers to the state of information when it is located on a secondary storage device (e.g., disk drive, tape drive) within an organizational information system. Applications and application users generate information throughout the course of their application use. 

User data generated, as well as application-specific configuration data, needs to be protected. Organizations may choose to employ different mechanisms to achieve confidentiality and integrity protections, as appropriate. 

If the confidentiality and integrity of application data is not protected, the data will be open to compromise and unauthorized modification.'
  desc 'check', 'Run the PowerShell command below to determine database encryption status:
$LogicalServerName = "myServerName"
$RGname = "myRG"
$DBName = "myDatabaseName"
Get-AzSqlDatabaseTransparentDataEncryption -ServerName $LogicalServerName -ResourceGroupName $RGname -DatabaseName $Dbname

If the application owner and Authorizing Official have determined that encryption of data at rest is required and the "EncryptionState" column returns "UNENCRYPTED" or "DECRYPTION_IN_PROGRESS", this is a finding.'
  desc 'fix', 'If Azure SQL Database Transparent Data Encryption is disabled, use the Set-AzSqlDatabaseTransparentDataEncryption command to enable.

$LogicalServerName = "myServerName"
$RGname = "myRG"
$DBName = "myDatabaseName"
$TDEstate = "Enabled"
Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName $RGname -ServerName $LogicalServerName -DatabaseName $DBname -State $TDEstate'
  impact 0.7
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59012r871141_chk'
  tag severity: 'high'
  tag gid: 'V-255339'
  tag rid: 'SV-255339r879642_rule'
  tag stig_id: 'ASQL-00-009500'
  tag gtitle: 'SRG-APP-000231-DB-000154'
  tag fix_id: 'F-58956r871142_fix'
  tag 'documentable'
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
