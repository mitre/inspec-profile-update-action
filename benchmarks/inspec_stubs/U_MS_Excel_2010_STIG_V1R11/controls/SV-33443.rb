control 'SV-33443' do
  title 'Macro storage must be in Personal macro workbooks.'
  desc 'The Record Macro dialog box includes a drop-down menu allowing users to choose whether to store the new macro in the current workbook, a new workbook, or their personal macro workbook (Personal.xlsb), a hidden workbook that opens every time Excel starts.
By default, Excel displays the Record Macro dialog box with “This Workbook already selected” in the drop-down menu. If a user saves a macro in the active workbook and then distributes the workbook to others, the macro is distributed along with the workbook, which could put workbook data at risk if the macro is triggered accidentally or intentionally.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center “Store macro in Personal Macro Workbook by default” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\options\\binaryoptions

Criteria: If the value fGlobalSheet_37_1 is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center “Store macro in Personal Macro Workbook by default” to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-33926r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17804'
  tag rid: 'SV-33443r1_rule'
  tag stig_id: 'DTOO145 - Excel'
  tag gtitle: 'DTOO145 - Store macro in workbook'
  tag fix_id: 'F-29615r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
