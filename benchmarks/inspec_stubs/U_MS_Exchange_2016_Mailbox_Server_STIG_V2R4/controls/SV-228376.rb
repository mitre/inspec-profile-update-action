control 'SV-228376' do
  title 'Exchange Mailboxes must be retained until backups are complete.'
  desc 'Backup and recovery procedures are an important part of overall system availability and integrity. Complete backups reduce the chance of accidental deletion of important information and make it possible to have complete recoveries.

It is not uncommon for users to receive and delete messages in the scope of a single backup cycle. This setting ensures at least one backup has been run on the mailbox store before the message physically disappears. By enabling this setting, all messages written to recipients who have accounts on this store will reside in backups even if they have been deleted by the user before the backup has run.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase| Select Name, Identity, RetainDeletedItemsUntilBackup

If the value of "RetainDeletedItemsUntilBackup" is not set to "True", this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase  -Identity <'IdentityName'> -RetainDeletedItemsUntilBackup $true

Note: The <IdentityName> value must be in single quotes."
  impact 0.5
  ref 'DPMS Target Microsoft Exchange 2016 Mailbox Server'
  tag check_id: 'C-30609r496924_chk'
  tag severity: 'medium'
  tag gid: 'V-228376'
  tag rid: 'SV-228376r612748_rule'
  tag stig_id: 'EX16-MB-000270'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-30594r496925_fix'
  tag 'documentable'
  tag legacy: ['SV-95377', 'V-80667']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
