control 'SV-53473' do
  title 'Files from the Internet zone must be opened in Protected View.'
  desc 'This policy setting allows for determining if files downloaded from the Internet zone open in Protected View. If enabling this policy setting, files downloaded from the Internet zone do not open in Protected View. If disabling or not configuring this policy setting, files downloaded from the Internet zone open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Do not open files from the Internet zone in Protected View" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\PowerPoint\\security\\protectedview

Criteria: If the value DisableInternetFilesInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2013 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Do not open files from the Internet zone in Protected View to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2013'
  tag check_id: 'C-47672r3_chk'
  tag severity: 'medium'
  tag gid: 'V-26614'
  tag rid: 'SV-53473r2_rule'
  tag stig_id: 'DTOO121'
  tag gtitle: 'DTOO121 - Files from the Internet zone'
  tag fix_id: 'F-46399r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
