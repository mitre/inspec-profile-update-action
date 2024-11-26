control 'SV-86029' do
  title 'Files in unsafe locations must be opened in Protected View.'
  desc 'This policy setting determines whether files located in unsafe locations will open in Protected View. If unsafe locations have not been specified, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations. If enabling this policy setting, files located in unsafe locations do not open in Protected View. If disabling or not configuring this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" is set to "Not Configured" or "Disabled". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\protectedview 

Criteria: If the value DisableUnsafeLocationsInPV is REG_DWORD = 0, this is not a finding.
If the value does not exist, this is not a finding.
If the value is REG_DWORD = 1, then this is a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2016 -> PowerPoint Options -> Security -> Trust Center -> Protected View "Do not open files in unsafe locations in Protected View" to "Not Configured" or "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2016'
  tag check_id: 'C-71805r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71405'
  tag rid: 'SV-86029r1_rule'
  tag stig_id: 'DTOO288'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77723r2_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
