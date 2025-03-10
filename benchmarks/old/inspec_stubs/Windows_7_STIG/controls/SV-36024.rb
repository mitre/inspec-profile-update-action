control 'SV-36024' do
  title 'The System event log must be configured to a minimum size requirement.'
  desc 'Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\System\\

Value Name:  MaxSize

Type:  REG_DWORD
Value:  0x00008000 (32768) (or greater)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> System -> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Windows 7'
  tag check_id: 'C-59311r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26582'
  tag rid: 'SV-36024r2_rule'
  tag stig_id: 'WINAU-100103'
  tag gtitle: 'Maximum Log Size - System'
  tag fix_id: 'F-63799r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
