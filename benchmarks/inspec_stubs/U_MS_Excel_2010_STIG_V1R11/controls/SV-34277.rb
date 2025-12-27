control 'SV-34277' do
  title 'Actions for Excel 95 workbooks must be configured to edit in protected view.'
  desc 'This policy setting allows for determining whether users can open, view, edit, or save Excel files with the format specified by the title. If enabling this policy setting, specify whether users can open, view, edit, or save files. The options that can be selected are below. Note: Not all options may be available for this policy setting. - Do not block: The file type will not be blocked. - Save blocked: Saving of the file type will be blocked. - Open/Save blocked, use open policy: Both opening and saving of the file type will be blocked. The file will open based on the policy setting configured in the "default file block behavior" key. - Block: Both opening and saving of the file type will be blocked, and the file will not open. - Open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit the file type will not be enabled. - Allow editing and open in Protected View: Both opening and saving of the file type will be blocked, and the option to edit will be enabled. If you disable or do not configure this policy setting, the file type will not be blocked.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “Excel 95 workbooks” must be “Enabled: Allow editing and open in Protected View".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security\\fileblock

Criteria: If the value XL95Workbooks is REG_DWORD = 5, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “Excel 95 workbooks” to “Enabled: Allow editing and open in Protected View".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34203r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26610'
  tag rid: 'SV-34277r2_rule'
  tag stig_id: 'DTOO108 - Excel'
  tag gtitle: 'DTOO108 - Excel 95 workbooks'
  tag fix_id: 'F-29897r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
