control 'SV-255336' do
  title 'Azure SQL Database must map the PKI-authenticated identity to an associated user account.'
  desc 'The DOD standard for authentication is DOD-approved PKI certificates. Once a PKI certificate has been validated, it must be mapped to an Azure SQL Database user account for the authenticated identity to be meaningful to Azure SQL Database and useful for authorization decisions.'
  desc 'check', 'To verify that Azure Active Directory is configured as the authentication type, use the following PowerShell commands: 

$LogicalServerName = "myServer" 
Get-AzSqlServer -ServerName $LogicalServerName | Get-AzSqlServerActiveDirectoryOnlyAuthentication

If AzureADOnlyAuthentication returns False, this is a finding.'
  desc 'fix', 'To set the Azure Active Directory Administrator, use the following PowerShell command: 

$LogicalServerName = "myServer" 
Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName "myResourceGroup" -ServerName $LogicalServerName -DisplayName "myAADIdentify"

Azure Active Directory Authentication can be enabled using either PowerShell or the Azure CLI.

To enable Azure Active Directory Authentication using PowerShell, use the commands below: 

######
###### Sets the AAD Admin in the SQL Server using PowerShell ######
######
$LogicalServerName = "myServer" 
$ResourceGroup = "myResourceGroup"
$DisplayName = "<AAD Principal>" 
$ObjectId = "<GUID for AAD Principal>"

Set-AzSqlServerActiveDirectoryAdministrator `
-ResourceGroupName $ResourceGroup `
-ServerName $LogicalServerName `
-DisplayName $DisplayName `
-ObjectId$ObjectId

#Sets AD Admin Only
Get-AzSqlServer -ServerName $LogicalServerName `
| Enable-AzSqlServerActiveDirectoryOnlyAuthentication

To enable Azure Active Directory Authentication using the Azure CLI, use the commands below:

######
###### Sets the AAD Admin in the SQL Server using the Azure CLI ######
######
az sql server ad-admin create `
--resource-group $ResourceGroup 
--server $LogicalServerName `
--display-name $DisplayName `
--object-id $ObjectId `

#Sets AD Admin Only
az sql server ad-only-auth enable `
--resource-group $ResourceGroup `
--name $LogicalServerName 

https://docs.microsoft.com/en-us/cli/azure/sql/server/ad-only-auth?view=azure-cli-latest
https://docs.microsoft.com/en-us/azure/azure-sql/database/authentication-aad-configure?tabs=azure-powershell'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59009r877264_chk'
  tag severity: 'medium'
  tag gid: 'V-255336'
  tag rid: 'SV-255336r877266_rule'
  tag stig_id: 'ASQL-00-008500'
  tag gtitle: 'SRG-APP-000177-DB-000069'
  tag fix_id: 'F-58953r877265_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
