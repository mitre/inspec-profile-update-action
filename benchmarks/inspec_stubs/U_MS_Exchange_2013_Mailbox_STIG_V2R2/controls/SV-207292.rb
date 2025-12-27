control 'SV-207292' do
  title 'The Exchange Public Folder database must not be overwritten by a restore.'
  desc 'Email system availability depends in part on best practice strategies for setting tuning configurations. Unauthorized or accidental restoration of public folder data risks data loss or corruption.  

This setting controls whether the public folder store can be overwritten by a restore from backup, which will cause loss of all information added after the backup was created. It should only be enabled during maintenance windows or following an outage (immediately before a restore is to be made), and cleared again immediately afterward.  

During production windows, this feature must be disabled.'
  desc 'check', 'If public folders are not used, this check is not applicable. 

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase| Select Name, Identity, AllowFileRestore

If the value of AllowFileRestore is not set to False, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase  -Identity <'IdentityName'> -AllowFileRestore $false

Note: The <IdentityName> value must be in quotes."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Mailbox Server'
  tag check_id: 'C-7550r393389_chk'
  tag severity: 'low'
  tag gid: 'V-207292'
  tag rid: 'SV-207292r615936_rule'
  tag stig_id: 'EX13-MB-000130'
  tag gtitle: 'SRG-APP-000231'
  tag fix_id: 'F-7550r393390_fix'
  tag 'documentable'
  tag legacy: ['SV-84613', 'V-69991']
  tag cci: ['CCI-001199']
  tag nist: ['SC-28']
end
