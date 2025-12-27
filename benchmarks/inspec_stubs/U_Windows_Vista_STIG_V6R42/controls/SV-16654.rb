control 'SV-16654' do
  title 'The system must be configured to generate error reports.'
  desc 'Enabling Windows Error Reporting generates information useful to system administrators and forensics analysts for diagnosing system problems and investigating intrusions.  If Windows Error Reporting is turned off, valuable system diagnostic and vulnerability information may be lost.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Registry Path:  \\SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Error Reporting\\

Value Name:  Disabled

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Error Reporting -> "Disable Windows Error Reporting" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows Vista'
  tag check_id: 'C-58129r1_chk'
  tag severity: 'medium'
  tag gid: 'V-15715'
  tag rid: 'SV-16654r3_rule'
  tag stig_id: 'WINER-000002'
  tag gtitle: 'WINER-000002'
  tag fix_id: 'F-62491r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']
end
