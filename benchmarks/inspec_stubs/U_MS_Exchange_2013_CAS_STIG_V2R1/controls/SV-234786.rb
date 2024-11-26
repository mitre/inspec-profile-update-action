control 'SV-234786' do
  title 'Exchange must have the Microsoft Active Sync directory removed.'
  desc 'To reduce the vectors through which a server can be attacked, unneeded application components should be disabled or removed. By default, a virtual directory is installed for Active Sync, and the Exchange application default has Active Sync disabled.

If an attacker were to intrude into an Exchange CA server and reactivate Active Sync, this attack vector could once again be open, provided the virtual directory is present.

Once removed, the Active Sync functionality cannot be used without restoring the virtual directory, not a trivial process.'
  desc 'check', 'Open the Exchange Management Shell and enter the following command:

Get-ActiveSyncVirtualDirectory | Select Server, Name, Identity, Path

If the value of Path (the actual directory path) exists, this is a finding.'
  desc 'fix', 'Open an Exchange Command Shell and enter the following command:

Remove-ActiveSyncVirtualDirectory <ServerName>\\Microsoft-Server-ActiveSync -Confirm $true

Note: The physical directory must also be deleted.'
  impact 0.3
  ref 'DPMS Target Microsoft Exchange 2013 Client Access Server'
  tag check_id: 'C-37972r617297_chk'
  tag severity: 'low'
  tag gid: 'V-234786'
  tag rid: 'SV-234786r617299_rule'
  tag stig_id: 'EX13-CA-000110'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-37935r617298_fix'
  tag 'documentable'
  tag legacy: ['SV-84381', 'V-69759']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
