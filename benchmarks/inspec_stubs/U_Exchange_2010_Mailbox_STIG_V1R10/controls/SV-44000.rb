control 'SV-44000' do
  title 'Public Folder stores must be retained until backups are complete.'
  desc 'Backup and recovery procedures are an important part of overall system availability and integrity.   Complete backups reduce the chance of accidental deletion of important information, and make it possible to have complete recoveries.  
  
It is not uncommon for users to receive and delete documents in the scope of a single backup cycle.   This setting ensures at least one backup has been run on the folder store before the message physically disappears.  By enabling this setting, all messages written to recipients who have accounts on this store will reside in backups even if they have been deleted by the user before the backup has run.'
  desc 'check', "If public folders are not used this check is NA. 

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase| Select Name, Identity, RetainDeletedItemsUntilBackup

If the value of 'RetainDeletedItemsUntilBackup' is not set to 'True', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase <'PublicFolderDatabaseName'> -RetainDeletedItemsUntilBackup $true"
  impact 0.5
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41686r1_chk'
  tag severity: 'medium'
  tag gid: 'V-33580'
  tag rid: 'SV-44000r1_rule'
  tag stig_id: 'Exch-1-112'
  tag gtitle: 'Exch-1-112'
  tag fix_id: 'F-37471r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
