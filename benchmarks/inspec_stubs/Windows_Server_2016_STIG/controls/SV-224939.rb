control 'SV-224939' do
  title 'The System event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System\\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2016'
  tag check_id: 'C-26630r465719_chk'
  tag severity: 'medium'
  tag gid: 'V-224939'
  tag rid: 'SV-224939r877391_rule'
  tag stig_id: 'WN16-CC-000320'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-26618r465720_fix'
  tag 'documentable'
  tag legacy: ['SV-88221', 'V-73557']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
