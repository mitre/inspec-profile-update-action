control 'SV-53726' do
  title 'The Save commands default file format must be configured.'
  desc 'When users create new Excel files, Excel 2013 saves them in the new *.xlsx format. Ensure this setting is enabled to specify all new files are created in Excel 2013. If a new file is created in an earlier format, some users may not be able to open or use the file, or they may choose a format that is less secure than the Excel 2013 format. Users can still select a specific format when they save files, but they cannot change the default of this setting from the "Excel Options" dialog box. This enforced user behavior ensures any change to the file format requires additional deliberate user interaction.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Save "default file format" is set to "Enabled (Excel Workbook *.xlsx)". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\options

Criteria: If the value DefaultFormat is REG_DWORD =  0x00000033(hex) or 51 (Decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Save "default file format" to "Enabled (Excel Workbook *.xlsx)".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47812r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17521'
  tag rid: 'SV-53726r1_rule'
  tag stig_id: 'DTOO139'
  tag gtitle: 'DTOO139 - Save files default format'
  tag fix_id: 'F-46635r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
