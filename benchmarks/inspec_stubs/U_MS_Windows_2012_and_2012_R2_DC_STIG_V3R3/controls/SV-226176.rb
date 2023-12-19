control 'SV-226176' do
  title 'Remote Assistance log files must be generated.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting will turn on session logging for Remote Assistance connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Registry Path: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: LoggingEnabled

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Turn on session logging" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows Server 2012-2012 R2 Domain Controller'
  tag check_id: 'C-27878r475851_chk'
  tag severity: 'low'
  tag gid: 'V-226176'
  tag rid: 'SV-226176r794500_rule'
  tag stig_id: 'WN12-CC-000062'
  tag gtitle: 'SRG-OS-000480-GPOS-00227'
  tag fix_id: 'F-27866r475852_fix'
  tag 'documentable'
  tag legacy: ['SV-53133', 'V-15707']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
