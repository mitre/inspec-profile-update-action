control 'SV-207294' do
  title 'The Exchange Mailbox database must not be overwritten by a restore.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Unauthorized or accidental restoration of mailbox data risks data loss or corruption.   

This setting controls whether the mailbox store can be overwritten by a backup, which will cause loss of all information added after the backup was created. It should only be enabled during maintenance windows or following an outage (immediately before a restore is to be made), and cleared again immediately afterward.

During production windows, this feature must be disabled.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-MailboxDatabase| Select Name, Identity, AllowFileRestore

If the value of AllowFileRestore is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-MailboxDatabase  -Identity <'IdentityName'> -AllowFileRestore $false

Note: The <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7552r393395_chk'
  tag severity: 'low'
  tag gid: 'V-207294'
  tag rid: 'SV-207294r615936_rule'
  tag stig_id: 'EX13-MB-000140'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-7552r393396_fix'
  tag 'documentable'
  tag legacy: ['SV-84617', 'V-69995']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
