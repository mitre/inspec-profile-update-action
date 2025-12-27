control 'SV-36023' do
  title 'The Setup event log must be configured to a minimum size requirement.'
  desc 'Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Setup\\

Value Name:  MaxSize

Type:  REG_DWORD
Value:  0x00008000 (32768) (or greater)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> Setup -> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-59297r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26581'
  tag rid: 'SV-36023r2_rule'
  tag stig_id: 'WINAU-100102'
  tag gtitle: 'Maximum Log Size - Setup'
  tag fix_id: 'F-63785r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
