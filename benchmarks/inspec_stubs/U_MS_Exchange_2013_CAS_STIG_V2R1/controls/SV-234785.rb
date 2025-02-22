control 'SV-234785' do
  title 'Exchange must have the Public Folder virtual directory removed if not in use by the site.'
  desc 'To reduce the vectors through which a server can be attacked, unneeded application components should be disabled or removed.

By default, a virtual directory is installed for Public Folders. If an attacker were to intrude into an Exchange CA server and be able to access the Public Folder website, it would provide an additional attack vector, provided the virtual directory was present.

Once removed, the Public functionality cannot be used without restoring the virtual directory.'
  desc 'check', 'Review the Email Domain Security Plan (EDSP).

Determine if public folders are being used.

Open the Exchange Management Shell and enter the following command:

Get-PublicFolder | Select Name, Identity

Note: The value returns a root directory and subdirectories.

If public folders are not in use and directories exist or are being used and are not documented in the EDSP, this is a finding.'
  desc 'fix', "Open the Exchange Management Shell and enter the following command:

Remove-PublicFolder -Identity 'IdentityName' -Recurse:$True

Note: This command deletes the public folder Directory Folder and all its child public folders."
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37971r617294_chk'
  tag severity: 'low'
  tag gid: 'V-234785'
  tag rid: 'SV-234785r617296_rule'
  tag stig_id: 'EX13-CA-000105'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-37934r617295_fix'
  tag 'documentable'
  tag legacy: ['SV-84379', 'V-69757']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
