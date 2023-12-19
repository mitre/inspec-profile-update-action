control 'SV-33435' do
  title 'Load pictures from Web pages must be disallowed.'
  desc 'When users open Web pages in Excel, Excel loads any graphics included in the pages, regardless of whether they were originally created in Excel. Allowing Excel to load graphics created in other programs can make Excel vulnerable to possible future zero-day attacks using graphic files as an attack vector. If such an event occurs, this setting can be used to mitigate the vulnerability.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Advanced -> Web Options -> General “Load pictures from Web pages not created in Excel” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\internet

Criteria: If the value DoNotLoadPictures is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Advanced -> Web Options -> General “Load pictures from Web pages not created in Excel” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33918r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17751'
  tag rid: 'SV-33435r1_rule'
  tag stig_id: 'DTOO152 - Excel'
  tag gtitle: 'DTOO152 - Load pics from Web not in Excel'
  tag fix_id: 'F-29607r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
