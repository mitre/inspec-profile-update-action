control 'SV-33439' do
  title 'AutoRepublish Warning Alert must be provided.'
  desc 'AutoRepublish is a feature in Excel allowing workbooks to be automatically republished to the World Wide Web each time the workbook is saved. A number of changes might need to be made to allow the workbook to be successfully published, including the following:
•       External references are converted to values.
•       Hidden formulas become visible.
•       The Set precision as displayed option, which appears beneath the “When calculating this workbook” heading in the Advanced section of the Excel Options dialog box, is no longer available.
These types of changes can mean the version on the Web page might not be the same as the Excel file. By default, a message dialog box appears every time the user saves a published workbook when AutoRepublish is enabled. From this dialog box, the user can disable AutoRepublish temporarily or permanently, or select “Do not show this message again” to prevent the dialog box from appearing after every save. If the user selects “Do not show this message again”, Excel will continue to automatically republish the data after every save without informing the user.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Save “Do not show AutoRepublish warning alert” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options

Criteria: If the value DisableAutoRepublishWarning is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Save “Do not show AutoRepublish warning alert” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33922r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17744'
  tag rid: 'SV-33439r1_rule'
  tag stig_id: 'DTOO141 - Excel'
  tag gtitle: 'DTOO141 - AutoRepublish Warning Alert'
  tag fix_id: 'F-29611r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
