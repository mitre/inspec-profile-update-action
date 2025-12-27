control 'SV-16653' do
  title 'The system must be configured to save Error Reporting events and messages to the system event log.'
  desc 'Maintaining an audit trail of system activity logs can help identify configuration errors, troubleshoot service disruptions, and analyze compromises that have occurred, as well as detect attacks.  This setting ensures that Error Reporting events will be saved in the system event log.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  LoggingDisabled

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Disable logging" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58123r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15714'
  tag rid: 'SV-16653r2_rule'
  tag stig_id: 'WINER-000003'
  tag gtitle: 'WINER-000003'
  tag fix_id: 'F-15606r2_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
