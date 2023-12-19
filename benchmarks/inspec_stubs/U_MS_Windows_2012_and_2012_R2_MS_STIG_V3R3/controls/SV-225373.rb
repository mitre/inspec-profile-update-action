control 'SV-225373' do
  title 'The System event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System\\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> System >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Windows Server 2012-2012 R2 Member Server'
  tag check_id: 'C-27072r471461_chk'
  tag severity: 'medium'
  tag gid: 'V-225373'
  tag rid: 'SV-225373r569185_rule'
  tag stig_id: 'WN12-CC-000087'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-27060r471462_fix'
  tag 'documentable'
  tag legacy: ['SV-52963', 'V-26582']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
