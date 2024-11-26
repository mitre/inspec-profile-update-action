control 'SV-255377' do
  title 'Azure SQL Database must offload audit data to a separate log management facility; this must be continuous and in near real time for systems with a network connection to the storage facility and weekly or more often for stand-alone systems.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Offloading is a common process in information systems with limited audit storage capacity. 

Azure SQL Database may write audit records blob storage, log analytics, or event hub. Multiple methods should be used to ensure audit files are retained, or immutable storage should be used.'
  desc 'check', 'Review the system documentation for a description of how audit records are stored. 
 
1. Review the Auditing link in the Azure Portal for the SQL Database. Ensure audit logs are written to more than one storage system. If not, navigate to the Storage Container where the audits are stored via the Portal. 
2. Select "Containers". 
3. Select the ellipsis on the container for the audit storage. 
4. Select "Access Policy". 

Verify that an Immutable Blob Storage policy has been added to the audit container. If Azure audit logs are written to only one storage system or immutable storage is not enabled, this is a finding.'
  desc 'fix', 'Enable immutable storage so that audit logs cannot be modified or deleted accidently.
https://docs.microsoft.com/en-us/azure/storage/blobs/immutable-policy-configure-container-scope?tabs=azure-portal

To configure a time-based retention policy on a container with the Azure portal, follow these steps:

1. Navigate to the desired container.
2. Select "More" on the right, then select "Access policy".
3. In the Immutable blob storage section, select "Add policy".
4. In the Policy type field, select "Time-based retention", and specify the retention period in days.
5. To create a policy with container scope, do not check the box for "Enable" version-level immutability.
6. If desired, select "Allow additional protected appends" to enable writes to append blobs that are protected by an immutability policy.

PowerShell:
Set-AzRmStorageContainerImmutabilityPolicy -ResourceGroupName <resource-group> `
    -StorageAccountName <storage-account> `
    -ContainerName <container> `
    -ImmutabilityPeriod 10

Alternatively, enable at least two types of audit storage for the Azure SQL Database.
In the Azure Portal, select "Auditing".
Check at least two of the available storage types and select "Save".'
  impact 0.5
  ref 'DPMS Target MS Azure SQL DB'
  tag check_id: 'C-59050r877254_chk'
  tag severity: 'medium'
  tag gid: 'V-255377'
  tag rid: 'SV-255377r877255_rule'
  tag stig_id: 'ASQL-00-015900'
  tag gtitle: 'SRG-APP-000515-DB-000318'
  tag fix_id: 'F-58994r871256_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
