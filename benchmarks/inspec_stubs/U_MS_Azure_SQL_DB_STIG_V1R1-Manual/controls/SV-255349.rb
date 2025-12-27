control 'SV-255349' do
  title 'Azure SQL Database must maintain the confidentiality and integrity of information during reception.'
  desc 'Information can be either unintentionally or maliciously disclosed or modified during reception, including, for example, during aggregation, at protocol transformation points, and during packing/unpacking. These unauthorized disclosures or modifications compromise the confidentiality or integrity of the information.

This requirement applies only to those applications that are either distributed or can allow access to data nonlocally. Use of this requirement will be limited to situations where the data owner has a strict requirement for ensuring data integrity and confidentiality is maintained at every step of the data transfer and handling process. 

When receiving data, Azure SQL Database, associated applications, and infrastructure must leverage protection mechanisms.'
  desc 'check', "Document reception protection mechanisms based on organizationally defined requirements, if this documentation does not exist this is a finding.

Validate that reception protection mechanisms match documentation of organizationally defined requirements, if discrepancies exist this is a finding.

Run the following PowerShell  script to check the TLS version:
$ResourceGroupName = '<Resource Group Name>'
Get-AzSqlServer -ResourceGroupName $ResourceGroupName | Format-Table ServerName,MinimalTlsVersion

Verify that the minimum TLS version property is set to the latest available TLS version. If a less secure TLS version is set, this is a finding."
  desc 'fix', 'Implement and document protective measures against unauthorized disclosure and modification during transmission reception.

https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings

https://docs.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture

https://docs.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59022r877259_chk'
  tag severity: 'medium'
  tag gid: 'V-255349'
  tag rid: 'SV-255349r877260_rule'
  tag stig_id: 'ASQL-00-012600'
  tag gtitle: 'SRG-APP-000442-DB-000379'
  tag fix_id: 'F-58966r871172_fix'
  tag 'documentable'
  tag cci: ['CCI-002422']
  tag nist: ['SC-8 (2)']
end
