control 'SV-53638' do
  title 'Open/Save actions for web pages and Excel 2003 XML spreadsheets must be blocked.'
  desc 'This policy setting allows for determining whether users can open, view, edit, or save Excel files with the format specified by the title'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Web pages and Excel 2003 XML spreadsheets" is set to "Enabled: Open/Save blocked, use open policy".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security\\fileblock

Criteria: If the value HtmlandXmlssFiles is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Web pages and Excel 2003 XML spreadsheets" to "Enabled: Open/Save blocked, use open policy".'
  impact 0.3
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47764r1_chk'
  tag severity: 'low'
  tag gid: 'V-26613'
  tag rid: 'SV-53638r2_rule'
  tag stig_id: 'DTOO120'
  tag gtitle: 'DTOO120 -Web pages and Excel 2003 XML spreadsheets'
  tag fix_id: 'F-46564r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
