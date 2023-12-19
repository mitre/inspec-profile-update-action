control 'SV-32465' do
  title 'Explorer Data Execution Prevention will be enabled.'
  desc 'This setting will prevent Data Execution Prevention from being turned off for Windows Explorer.'
  desc 'check', 'If the following registry value doesn’t exist or is not configured as specified, this is a finding:

Registry Hive:  HKEY_LOCAL_MACHINE
Subkey:  \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name:  NoDataExecutionPrevention

Type:  REG_DWORD
Value:  0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> Windows Explorer -> “Turn off Data Execution Prevention for Explorer” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Windows 2008 R2'
  tag check_id: 'C-26864r1_chk'
  tag severity: 'medium'
  tag gid: 'V-21980'
  tag rid: 'SV-32465r1_rule'
  tag gtitle: 'Explorer Data Execution Prevention'
  tag fix_id: 'F-22971r1_fix'
  tag 'documentable'
  tag responsibility: 'System Administrator'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
