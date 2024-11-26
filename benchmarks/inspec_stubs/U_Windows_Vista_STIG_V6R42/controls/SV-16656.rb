control 'SV-16656' do
  title 'The system must be configured to allow a local or DOD-wide collector to request additional error reporting diagnostic data to be sent.'
  desc 'Sending additional error reporting data provides valuable system diagnostic and vulnerability information that would otherwise not be generated nor collected.  This setting controls whether additional data in support of error reports can be sent to a local or DOD-wide reporting site.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  DontSendAdditionalData

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Do not send additional data" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58141r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15717'
  tag rid: 'SV-16656r2_rule'
  tag stig_id: 'WINER-000004'
  tag gtitle: 'WINER-000004'
  tag fix_id: 'F-62503r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
