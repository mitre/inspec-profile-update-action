control 'SV-253337' do
  title 'The Application event log size must be configured to 32768 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application\\

Value Name: MaxSize

Value Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO.

Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Application >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56790r829093_chk'
  tag severity: 'medium'
  tag gid: 'V-253337'
  tag rid: 'SV-253337r829095_rule'
  tag stig_id: 'WN11-AU-000500'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-56740r829094_fix'
  tag 'documentable'
  tag cci: ['CCI-001819']
  tag nist: ['CM-3 d']
end
