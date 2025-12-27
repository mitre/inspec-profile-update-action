control 'SV-48482' do
  title 'Explorer Data Execution Prevention must be enabled.'
  desc 'Data Execution Prevention (DEP) provides additional protection by performing  checks on memory to help prevent malicious code from running.  This setting will prevent Data Execution Prevention from being turned off for File Explorer.'
  desc 'check', 'If the following registry value does not exist or is not configured as specified, this is a finding:

Registry Hive: HKEY_LOCAL_MACHINE
Subkey: \\Software\\Policies\\Microsoft\\Windows\\Explorer\\

Value Name: NoDataExecutionPrevention

Type: REG_DWORD
Value: 0'
  desc 'fix', 'Configure the policy value for Computer Configuration -> Administrative Templates -> Windows Components -> File Explorer -> "Turn off Data Execution Prevention for Explorer" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Windows 8'
  tag check_id: 'C-45142r2_chk'
  tag severity: 'medium'
  tag gid: 'V-21980'
  tag rid: 'SV-48482r2_rule'
  tag stig_id: 'WN08-CC-000089'
  tag gtitle: 'Explorer Data Execution Prevention'
  tag fix_id: 'F-41607r1_fix'
  tag 'documentable'
  tag ia_controls: 'ECSC-1'
  tag cci: ['CCI-002824']
  tag nist: ['SI-16']
end
