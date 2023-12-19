control 'SV-34282' do
  title 'Open/Save actions for Web pages and Excel 2003 XML spreadsheets must be blocked.'
  desc 'This policy setting allows for determining whether users can open, view, edit, or save Excel files with the format specified by the title. If enabling this policy setting, specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting. - Do not block: The file type will not be blocked. - Save blocked: Saving of the file type will be blocked. - Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the "default file block behavior" key. - Block: Both opening and saving of the file type will be blocked, and the file will not open. - Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled. - Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. If you disable or do not configure this policy setting, the file type will not be blocked.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “Web pages and Excel 2003 XML spreadsheets” must be “Enabled: Open/Save blocked, use open policy".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security\\fileblock

Criteria: If the value HtmlandXmlssFiles is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “Web pages and Excel 2003 XML spreadsheets” to “Enabled: Open/Save blocked, use open policy".'
  impact 0.3
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34206r1_chk'
  tag severity: 'low'
  tag gid: 'V-26613'
  tag rid: 'SV-34282r2_rule'
  tag stig_id: 'DTOO120 - Excel'
  tag gtitle: 'DTOO120 -Web pages and Excel 2003 XML spreadsheets'
  tag fix_id: 'F-29900r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
