control 'SV-255344' do
  title 'Azure SQL Database must provide a warning to appropriate support staff when allocated audit record storage volume reaches 75 percent of maximum audit record storage capacity.'
  desc 'Auditing for Azure SQL Database tracks database events and writes them to an audit log in the Azure storage account, Log Analytics workspace, or Event Hubs.

Under normal conditions, the audit space allocated by an Azure Storage account can grow quite large.
Since a requirement exists to halt processing upon audit failure, a service outage would result.'
  desc 'check', 'Azure SQL Database must provide notice upon audit storage reaching capacity.
 
If no alert exists to notify support staff in the event the SQL Audit storage reaches 75 percent, this is a finding.

Verify if an Azure Rule exists with the following command example:

Get-AzAlertRule
   -ResourceGroupName <String>
   -Name <String>
   [-DetailedOutput]
   [-DefaultProfile <IAzureContextContainer>]
   [<CommonParameters>]

The Get-AzAlertRule cmdlet gets an alert rule by its name or URI, or all alert rules from a specified resource group.

If the monitoring or alert configuration is missing a rule that alerts if the storage account is 75 percent of maximum capacity, this is a finding.'
  desc 'fix', 'Utilize Alerts in Microsoft Azure Monitoring and/or third-party tools to configure the system to notify appropriate support staff immediately upon storage volume utilization reaching 75 percent.

https://docs.microsoft.com/en-us/azure/azure-monitor/alerts/alerts-overview'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59017r871156_chk'
  tag severity: 'medium'
  tag gid: 'V-255344'
  tag rid: 'SV-255344r871158_rule'
  tag stig_id: 'ASQL-00-011000'
  tag gtitle: 'SRG-APP-000359-DB-000319'
  tag fix_id: 'F-58961r871157_fix'
  tag 'documentable'
  tag cci: ['CCI-001855']
  tag nist: ['AU-5 (1)']
end
