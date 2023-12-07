control 'SV-226190' do
  title 'The Application event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to write events directly to an audit server, this is NA.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application\\

Value Name: MaxSize

Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows Server 2012-2012 R2 DC'
  tag check_id: 'C-27892r475893_chk'
  tag severity: 'medium'
  tag gid: 'V-226190'
  tag rid: 'SV-226190r852103_rule'
  tag stig_id: 'WN12-CC-000084'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-27880r475894_fix'
  tag 'documentable'
  tag legacy: ['SV-52966', 'V-26579']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
