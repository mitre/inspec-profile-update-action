control 'SV-255343' do
  title 'Azure SQL Database must be able to allocate audit record storage capacity in accordance with organization-defined audit record storage requirements.'
  desc 'To ensure sufficient storage capacity for the audit logs, the Azure SQL Database must be able to allocate audit record storage capacity. Although another requirement (SRG-APP-000515-DB-000318) mandates that audit data be offloaded to a centralized log management system, it remains necessary to provide space to serve as a buffer against outages and capacity limits of the offloading mechanism.

The task of allocating audit record storage capacity is usually performed during initial setup of Azure SQL Database and is closely associated with the DBA and system administrator roles. 
The DBA or system administrator will usually coordinate the allocation of physical drive space with the application owner/installer and the application will prompt the installer to provide the capacity information, the physical location of the disk, or both.

In determining the capacity requirements, consider such factors as the maximum storage account size for blob data is 5PB, the total number of users; expected number of concurrent users during busy periods; number and type of events being monitored; types and amounts of data being captured; the frequency/speed with which audit records are offloaded to the central log management system; and any limitations that exist on the Azure storage accounts ability to reuse the space formerly occupied by offloaded records.'
  desc 'check', 'Refer to the online documentation for the Azure SQL Database Audit configuration or the online documentation for the PowerShell cmdlet Get-AzSQLServerAudit using the links provided below. 

https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview#manage-auditing

https://docs.microsoft.com/en-us/powershell/module/az.sql/get-azsqlserveraudit?view=azps-6.4.0

Use the following PowerShell script to check for the proper configuration settings:

$FormatEnumerationLimit=-1
Get-AzSqlServerAudit -ResourceGroupName myResourceGroupName -ServerName myservername

If the AuditActionGroup does not contain the correct entries needed for the auditing requirements or if the BlobStorageTargetState, EventHubTargetState, or LogAnalyticsTargetState is disabled from the output of the PowerShell above, this is a finding.'
  desc 'fix', 'Review the Azure SQL Database Audit file configuration information. 
https://docs.microsoft.com/en-us/azure/azure-sql/database/auditing-overview#manage-auditing

There are multiple options for configuring where audit logs will be written. Logs can be written to an Azure Blob Storage with Azure storage account, to a Log Analytics workspace, or to Event Hub. Any combination of these options can be configured, and audit logs will be written to each. 

When writing logs to an Azure Storage account, the default value for retention period is "0" (unlimited retention).'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59016r877294_chk'
  tag severity: 'medium'
  tag gid: 'V-255343'
  tag rid: 'SV-255343r877294_rule'
  tag stig_id: 'ASQL-00-010900'
  tag gtitle: 'SRG-APP-000357-DB-000316'
  tag fix_id: 'F-58960r871154_fix'
  tag 'documentable'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
