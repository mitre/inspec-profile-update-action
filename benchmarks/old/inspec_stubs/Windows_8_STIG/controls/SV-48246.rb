control 'SV-48246' do
  title 'Remote Assistance log files must be generated.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting will turn on session logging for Remote Assistance connections.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows NT\\Terminal Services\\

Value Name: LoggingEnabled

Type: REG_DWORD
Value: 1'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> System -> Remote Assistance -> "Turn on session logging" to "Enabled".'
  impact 0.3
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-44925r1_chk'
  tag severity: 'low'
  tag gid: 'V-15707'
  tag rid: 'SV-48246r2_rule'
  tag stig_id: 'WN08-CC-000062'
  tag gtitle: 'Remote Assistance – Session Logging'
  tag fix_id: 'F-41382r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
