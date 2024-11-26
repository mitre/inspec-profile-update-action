control 'SV-85641' do
  title 'Macro storage must be in personal macro workbooks.'
  desc %q(This policy setting controls the default location for storing macros in Excel. If this policy setting is enabled, Excel stores macros in users' personal macro workbook. If you disable or do not configure this policy setting, Excel stores macros in the active workbook from which they are created. Note: In the user interface (UI), the "Store macro in" drop down list box in the Record Macro dialog box (Macros | Record Macro) allows users to choose whether to store the new macro in the current workbook, a new workbook, or their personal macro workbook (Personal.xlsb), a hidden workbook that opens every time Excel starts. By default, Excel displays the "Store macro in" box with "This Workbook" already selected in the drop-down list. If a user saves a macro in the active workbook and then distributes the workbook to others, the macro is distributed along with the workbook. If you enable this policy setting, Excel displays the "Store macro in" box with "Personal Macro Workbook" already selected. Users can still select one of the other two options in the drop-down menu.)
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center "Store macro in Personal Macro Workbook by default" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\options\\binaryoptions

Criteria: If the value fGlobalSheet_37_1 is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2016 -> Excel Options -> Security -> Trust Center "Store macro in Personal Macro Workbook by default" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2016'
  tag check_id: 'C-71445r2_chk'
  tag severity: 'medium'
  tag gid: 'V-71017'
  tag rid: 'SV-85641r1_rule'
  tag stig_id: 'DTOO145'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-77349r1_fix'
  tag 'documentable'
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
