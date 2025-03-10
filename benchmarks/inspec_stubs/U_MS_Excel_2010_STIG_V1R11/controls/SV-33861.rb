control 'SV-33861' do
  title 'Files from the Internet zone must be opened in Protected View.'
  desc 'This policy setting allows for determining if files downloaded from the Internet zone open in Protected View. If enabling this policy setting, files downloaded from the Internet zone do not open in Protected View. If disabling or not configuring this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> Protected View “Do not open files from the Internet zone in Protected View” must be set to “Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security\\protectedview

Criteria: If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> Protected View “Do not open files from the Internet zone in Protected View” to “Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34207r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26614'
  tag rid: 'SV-33861r1_rule'
  tag stig_id: 'DTOO121 - Excel'
  tag gtitle: 'DTOO121 - Files from the Internet zone'
  tag fix_id: 'F-29901r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
