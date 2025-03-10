control 'SV-53579' do
  title 'Files in unsafe locations must be opened in Protected View.'
  desc 'This policy setting determines if files located in unsafe locations will open in Protected View. If unsafe locations have not been specified, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations. If enabling this policy setting, files located in unsafe locations do not open in Protected View. If disabling or not configuring this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\security\\protectedview 

Criteria: If the value DisableUnsafeLocationsInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47727r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26615'
  tag rid: 'SV-53579r1_rule'
  tag stig_id: 'DTOO288'
  tag gtitle: 'DTOO288 - Files in unsafe locations'
  tag fix_id: 'F-46503r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
