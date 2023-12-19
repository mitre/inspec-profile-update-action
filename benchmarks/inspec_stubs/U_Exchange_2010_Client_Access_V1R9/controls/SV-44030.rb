control 'SV-44030' do
  title 'The Microsoft Active Sync directory must be removed.'
  desc 'To reduce the vectors through which a server can be attacked, unneeded application components should be disabled or removed.  By default, a virtual directory is installed for Active Sync, and the Exchange application default has Active Sync disabled.  

If an attacker were to intrude into an Exchange CA server and reactivate Active Sync, this attack vector could once again be open, provided the virtual directory is present.

Once removed, the Active Sync functionality cannot be used without restoring the virtual directory, not a trivial process.'
  desc 'check', "Open the Exchange Management Shell and enter the following command:

Get-ActiveSyncVirtualDirectory | Select Server, Name, Identity, Path

If the value of 'Path' (actual directory) exists, this is a finding."
  desc 'fix', 'Open an Exchange Command Shell and enter the following command:

Remove-ActiveSyncVirtualDirectory ServerName\\Microsoft-Server-Active-Sync -Confirm $true

NOTE: The physical directory must also be deleted.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange Server 2010'
  tag check_id: 'C-41717r1_chk'
  tag severity: 'low'
  tag gid: 'V-33610'
  tag rid: 'SV-44030r1_rule'
  tag stig_id: 'Exch-1-603'
  tag gtitle: 'Exch-1-603'
  tag fix_id: 'F-37502r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
end
