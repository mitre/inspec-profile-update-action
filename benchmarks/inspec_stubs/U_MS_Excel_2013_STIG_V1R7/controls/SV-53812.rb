control 'SV-53812' do
  title 'Macro storage must be in personal macro workbooks.'
  desc 'The Record Macro dialog box includes a drop-down menu allowing users to choose whether to store the new macro in the current workbook, a new workbook, or their personal macro workbook (Personal.xlsb), a hidden workbook that opens every time Excel starts.
By default, Excel displays the Record Macro dialog box with "This Workbook already selected" in the drop-down menu. If a user saves a macro in the active workbook and then distributes the workbook to others, the macro is distributed along with the workbook, which could put workbook data at risk if the macro is triggered accidentally or intentionally.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center "Store macro in Personal Macro Workbook by default" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\options\\binaryoptions

Criteria: If the value fGlobalSheet_37_1 is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center "Store macro in Personal Macro Workbook by default" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47884r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17804'
  tag rid: 'SV-53812r1_rule'
  tag stig_id: 'DTOO145'
  tag gtitle: 'DTOO145 - Store macro in workbook'
  tag fix_id: 'F-46721r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
