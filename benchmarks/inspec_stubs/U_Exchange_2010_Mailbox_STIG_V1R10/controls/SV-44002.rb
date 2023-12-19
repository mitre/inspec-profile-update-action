control 'SV-44002' do
  title 'Public Folder database must not be overwritten by a restore.'
  desc 'Email system availability depends in part on best practices strategies for setting tuning configurations.  Unauthorized or accidental restoration of public folder data risks data loss or corruption.  

This setting controls whether the public folder store can be overwritten by a restore from backup, which will cause loss of all information added after the backup was created.  It should only be enabled during maintenance windows or following an outage (immediately before a restore is to be made), and cleared again immediately afterwards.  

During production windows, this feature must be disabled.'
  desc 'check', "If public folders are not used this check is NA. 

Open the Exchange Management Shell and enter the following command:

Get-PublicFolderDatabase| Select Name, Identity, AllowFileRestore

If the value of 'AllowFileRestore' is not set to 'False', this is a finding."
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Set-PublicFolderDatabase <'PublicFolderDatabaseName'> -AllowFileRestore $false"
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41688r1_chk'
  tag severity: 'low'
  tag gid: 'V-33582'
  tag rid: 'SV-44002r1_rule'
  tag stig_id: 'Exch-1-115'
  tag gtitle: 'Exch-1-115'
  tag fix_id: 'F-37473r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
