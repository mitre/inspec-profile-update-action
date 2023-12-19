control 'SV-43991' do
  title 'The Public Folder virtual directory must be removed if not in use by the site.'
  desc 'To reduce the vectors through which a server can be attacked, unneeded application components should be disabled or removed.  

By default, a virtual directory is installed for Public Folders.  If an attacker were to intrude into an Exchange CA server and be able to access the public folder web site, it would provide an additional attack vector, provided the virtual directory was present.  

Once removed, the Public functionality cannot be used without restoring the virtual directory.'
  desc 'check', 'If public folders are in use this check is NA.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolder | Select Name, Identity

If public folders are not in use and directories exist, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Remove-PublicFolder -Identity <'Identity'> -Server <'ServerName'> -Recurse: $true

Note: This command removes both the root directory and any subdirectories."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41677r2_chk'
  tag severity: 'low'
  tag gid: 'V-33571'
  tag rid: 'SV-43991r1_rule'
  tag stig_id: 'Exch-1-103'
  tag gtitle: 'Exch-1-103'
  tag fix_id: 'F-37462r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
