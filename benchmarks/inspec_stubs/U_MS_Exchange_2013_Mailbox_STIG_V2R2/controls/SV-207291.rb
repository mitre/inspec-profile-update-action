control 'SV-207291' do
  title 'Exchange Public Folder stores must be retained until backups are complete.'
  desc 'Backup and recovery procedures are an important part of overall system availability and integrity. Complete backups reduce the chance of accidental deletion of important information and make it possible to have complete recoveries.  
  
It is not uncommon for users to receive and delete documents in the scope of a single backup cycle. This setting ensures at least one backup has been run on the folder store before the message physically disappears. By enabling this setting, all messages written to recipients who have accounts on this store will reside in backups even if they have been deleted by the user before the backup has run.'
  desc 'check', 'If public folders are not used, this check is not applicable. 

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase | Select Name, Identity, RetainDeletedItemsUntilBackup

If the value of RetainDeletedItemsUntilBackup is not set to True, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase -Identity <'IdentityName'> -RetainDeletedItemsUntilBackup $true

Note: The <IdentityName> value must be in quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7549r393386_chk'
  tag severity: 'medium'
  tag gid: 'V-207291'
  tag rid: 'SV-207291r615936_rule'
  tag stig_id: 'EX13-MB-000125'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-7549r393387_fix'
  tag 'documentable'
  tag legacy: ['SV-84611', 'V-69989']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
