control 'SV-33695' do
  title 'The Security event log must be configured to a minimum size requirement.'
  desc 'Inadequate log size will cause the log to fill up quickly.  This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

Value Name:  MaxSize

Type:  REG_DWORD
Value:  0x00030000 (196608) (or greater)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, this is NA.  This must be documented with the ISSO.
Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Event Log Service -> Security -> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-59285r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26580'
  tag rid: 'SV-33695r2_rule'
  tag stig_id: 'WINAU-100101'
  tag gtitle: 'Maximum Log Size - Security'
  tag fix_id: 'F-63773r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
