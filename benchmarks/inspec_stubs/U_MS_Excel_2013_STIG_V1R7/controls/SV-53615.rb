control 'SV-53615' do
  title 'Actions for Excel 95-97 workbooks and templates must be configured to edit in Protected View.'
  desc 'This setting specifies whether users can open, view, edit, or save files saved in the specified format. Enabling block of the specified format mitigates zero-day security attacks (which are attacks that occur between the time that a vulnerability becomes publicly known and a software update or service pack is available) by temporarily preventing users from opening specific types of files and to prevent a user from opening files that have been saved in earlier and pre-release (beta) Microsoft Office formats.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Excel 95-97 workbooks and templates" is set to "Enabled: Allow editing and open in Protected View".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\office\\15.0\\excel\\security\\fileblock

Criteria: If the value XL9597WorkbooksandTemplates is REG_DWORD = 5, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Excel 95-97 workbooks and templates" to "Enabled: Allow editing and open in Protected View".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47749r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26611'
  tag rid: 'SV-53615r1_rule'
  tag stig_id: 'DTOO109'
  tag gtitle: 'DTOO109 - Excel 95-97 workbooks and templates'
  tag fix_id: 'F-46541r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
