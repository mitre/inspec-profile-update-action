control 'SV-226077' do
  title 'The time synchronization tool must be configured to enable logging of time source switching.'
  desc 'When a time synchronization tool executes, it may switch between time sources according to network or server contention.  If switches between time sources are not logged, it may be difficult or impossible to detect malicious activity or availability problems.'
  desc 'check', 'Verify logging is configured to capture time source switches.

If the Windows Time Service is used, verify the following registry value.  If it is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3

If another time synchronization tool is used, review the available configuration options and logs.  If the tool has time source logging capability and it is not enabled, this is a finding.'
  desc 'fix', 'Configure the time synchronization tool to log time source switching. If the Windows Time Service is used, configure the following registry value.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27779r475554_chk'
  tag severity: 'low'
  tag gid: 'V-226077'
  tag rid: 'SV-226077r794796_rule'
  tag stig_id: 'WN12-AD-000008-DC'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27767r794795_fix'
  tag 'documentable'
  tag legacy: ['SV-51182', 'V-8324']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
