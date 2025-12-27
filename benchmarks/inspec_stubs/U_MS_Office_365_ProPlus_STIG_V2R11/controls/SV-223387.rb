control 'SV-223387' do
  title 'Files in unsafe locations must be opened in Protected view in PowerPoint.'
  desc 'This policy setting determines whether files located in unsafe locations will open in Protected View. If unsafe locations have not been specified, only the "Downloaded Program Files" and "Temporary Internet Files" folders are considered unsafe locations. If enabling this policy setting, files located in unsafe locations do not open in Protected View. If disabling or not configuring this policy setting, files located in unsafe locations open in Protected View.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Do not open files in unsafe locations in Protected View" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\protectedview

If the value DisableUnsafeLocationsInPV is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Protected View "Do not open files in unsafe locations in Protected View" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25060r442380_chk'
  tag severity: 'medium'
  tag gid: 'V-223387'
  tag rid: 'SV-223387r879628_rule'
  tag stig_id: 'O365-PT-000011'
  tag gtitle: 'SRG-APP-000207'
  tag fix_id: 'F-25048r442381_fix'
  tag 'documentable'
  tag legacy: ['SV-108949', 'V-99845']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
