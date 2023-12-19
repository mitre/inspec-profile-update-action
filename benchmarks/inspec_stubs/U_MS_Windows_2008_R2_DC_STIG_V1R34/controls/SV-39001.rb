control 'SV-39001' do
  title 'The time synchronization tool must be configured to enable logging of  time source switching.'
  desc 'When a time synchronization tool executes, it may switch between time sources according to network or server contention. If switches between time sources are not logged, it may be difficult or impossible to detect malicious activity or availability problems.'
  desc 'check', 'Verify logging is configured to capture time source switches.

If the Windows Time Service is used, verify the following registry value.  If it is not configured as specified, this is a finding.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3

If another time synchronization tool is used, review the available configuration options and logs.  If the tool has time source logging capability and it is not enabled, this is a finding.'
  desc 'fix', 'Configure the time synchronization tool to log time source switching.  If the Windows Time Service is used, configure the following registry value.

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\System\\CurrentControlSet\\Services\\W32Time\\Config\\

Value Name: EventLogFlags

Type: REG_DWORD
Value: 2 or 3'
  impact 0.3
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-48681r2_chk'
  tag severity: 'low'
  tag gid: 'V-8324'
  tag rid: 'SV-39001r2_rule'
  tag stig_id: 'DS00.0151_2008_R2'
  tag gtitle: 'Time Synchronization Source Logging'
  tag fix_id: 'F-47804r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
