control 'SV-85635' do
  title 'The Save commands default file format must be configured.'
  desc 'This policy setting controls the default file format for saving workbooks in Excel. If you enable this policy setting, you can set the default file format for Excel from among the following options:- Excel Workbook (.xlsx). This option is the default configuration in Excel 2016.- Excel Macro-Enabled Workbook (.xlsm)- Excel Binary Workbook (.xlsb)- Web Page (.htm; .html)- Excel 97-2003 Workbook (.xls)- Excel 5.0/95 Workbook (.xls)- OpenDocument Spreadsheet (*.ods). Users can choose to save workbooks in a different file format than the default. If you disable or you do not configure this policy setting, Excel saves new workbooks in the Office Open XML format with an .xlsx extension.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Save "default file format" is set to "Enabled: (Excel Workbook *.xlsx)". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\options

Criteria: If the value DefaultFormat is REG_DWORD =  0x00000033(hex) or 51 (Decimal), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Save "default file format" to "Enabled: (Excel Workbook *.xlsx)".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71439r3_chk'
  tag severity: 'medium'
  tag gid: 'V-71011'
  tag rid: 'SV-85635r1_rule'
  tag stig_id: 'DTOO139'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-77343r2_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
