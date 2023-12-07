control 'SV-29488' do
  title 'Windows event log sizes must meet minimum requirements.'
  desc 'Inadequate log size will cause the log to fill up quickly. This may prevent audit events from being recorded properly and require frequent attention by administrative personnel.'
  desc 'check', 'If the system is configured to send audit records directly to an audit server, this is NA.

If the following registry values do not exist or are not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE

Registry Path: \\SOFTWARE\\Policies\\Microsoft\\Windows\\EventLog\\Application\\
Value Name: MaxSize
Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)

Registry Path: \\SOFTWARE \\Policies\\Microsoft\\Windows\\EventLog\\Security\\
Value Name: MaxSize
Type: REG_DWORD
Value: 0x00030000 (196608) (or greater)

Registry Path: \\SOFTWARE \\Policies\\Microsoft\\Windows\\EventLog\\Setup\\
Value Name: MaxSize
Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)

Registry Path: \\SOFTWARE \\Policies\\Microsoft\\Windows\\EventLog\\System\\
Value Name: MaxSize
Type: REG_DWORD
Value: 0x00008000 (32768) (or greater)'
  desc 'fix', 'Configure the following policy values as listed below:

Computer Configuration >> Administrative Templates >> Windows Components >> Event Log Service >> 

Application >> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.
Security >> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "196608" or greater.
Setup >> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.
System >> "Maximum Log Size (KB)" to "Enabled" with a "Maximum Log Size (KB)" of "32768" or greater.'
  impact 0.5
  ref 'DPMS Target Windows 2008'
  tag check_id: 'C-66229r1_chk'
  tag severity: 'medium'
  tag gid: 'V-1118'
  tag rid: 'SV-29488r2_rule'
  tag gtitle: 'Event Log Sizes'
  tag fix_id: 'F-71599r3_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001849']
  tag nist: ['AU-4']
end
