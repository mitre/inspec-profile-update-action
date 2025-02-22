control 'SV-253338' do
  title 'The Security event log size must be configured to 1024000 KB or greater.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA. This must be documented with the ISSO.

If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Security\\

Value Name: MaxSize

Value Type: REG_DWORD
Value: 0x000fa000 (1024000) (or greater)'
  desc 'fix', 'Configure the policy value for Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> Security >> "Specify the maximum log file size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "1024000" or greater.

If the system is configured to send audit records directly to an audit server, this must be documented with the ISSO.'
  impact 0.5
  ref 'DPMS Target Microsoft Windows 11'
  tag check_id: 'C-56791r829096_chk'
  tag severity: 'medium'
  tag gid: 'V-253338'
  tag rid: 'SV-253338r829098_rule'
  tag stig_id: 'WN11-AU-000505'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag fix_id: 'F-56741r829097_fix'
  tag 'documentable'
  tag cci: ['CCI-001819']
  tag nist: ['CM-3 d']
end
