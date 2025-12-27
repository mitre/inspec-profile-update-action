control 'SV-53820' do
  title 'The loading of images from web pages must not be allowed.'
  desc 'When users open web pages in Excel, Excel loads any graphics included in the pages, regardless of whether or not they were originally created in Excel. Allowing Excel to load graphics created in other programs can make Excel vulnerable to possible future zero-day attacks using graphic files as an attack vector. If such an event occurs, this setting can be used to mitigate the vulnerability.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Advanced -> Web Options -> General "Load pictures from Web pages not created in Excel" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\internet

Criteria: If the value "DoNotLoadPictures" is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Advanced -> Web Options -> General "Load pictures from Web pages not created in Excel" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47887r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17751'
  tag rid: 'SV-53820r1_rule'
  tag stig_id: 'DTOO152'
  tag gtitle: 'DTOO152 - Load pics from Web not in Excel'
  tag fix_id: 'F-46728r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
