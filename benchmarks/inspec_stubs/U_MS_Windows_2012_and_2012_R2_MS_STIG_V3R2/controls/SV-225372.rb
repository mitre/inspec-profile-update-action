control 'SV-225372' do
  title 'The Setup event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup\\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Setup >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27071r471458_chk'
  tag severity: 'medium'
  tag gid: 'V-225372'
  tag rid: 'SV-225372r569185_rule'
  tag stig_id: 'WN12-CC-000086'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-27059r471459_fix'
  tag 'documentable'
  tag legacy: ['SV-52964', 'V-26581']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
