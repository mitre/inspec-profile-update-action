control 'SV-85675' do
  title 'Files from the Internet zone must be opened in Protected View.'
  desc 'This policy setting allows for determining if files downloaded from the Internet zone open in Protected View. If enabling this policy setting, files downloaded from the Internet zone do not open in Protected View. If disabling or not configuring this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center -> Protected View "Do not open files from the Internet zone in Protected View" is set to "Not Configured" or "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\word\\security\\protectedview

Criteria: If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding.
If the value does not exist, this is not a finding.
If the value is REG_DWORD = 1, then this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2016 -> Word Options -> Security -> Trust Center -> Protected View "Do not open files from the Internet zone in Protected View" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2016'
  tag check_id: 'C-71479r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71051'
  tag rid: 'SV-85675r1_rule'
  tag stig_id: 'DTOO121'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-77383r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
