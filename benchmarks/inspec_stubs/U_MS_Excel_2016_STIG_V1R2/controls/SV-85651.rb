control 'SV-85651' do
  title 'Files in unsafe locations must be opened in Protected View.'
  desc 'This policy setting lets you determine if files located in unsafe locations will open in Protected View.  If you have not specified unsafe locations, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations. If you enable this policy setting, files located in unsafe locations do not open in Protected View. If you disable or do not configure this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" is set to "Not Configured" or "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\protectedview

Criteria: If the value DisableUnsafeLocationsInPV is REG_DWORD = 0, this is not a finding.
If the value does not exist, this is not a finding.
If the value is REG_DWORD = 1, then this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71455r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71027'
  tag rid: 'SV-85651r1_rule'
  tag stig_id: 'DTOO288'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77359r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
