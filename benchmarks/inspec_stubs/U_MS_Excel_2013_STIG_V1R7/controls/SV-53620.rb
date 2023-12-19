control 'SV-53620' do
  title 'Open/Save actions for Dif and Sylk files must be blocked.'
  desc 'This setting specifies whether users can open, view, edit, or save files saved in the specified format. Enabling block of the specified format mitigates zero-day security attacks (which are attacks that occur between the time that a vulnerability becomes publicly known and a software update or service pack is available) by temporarily preventing users from opening specific types of files and to prevent a user from opening files that have been saved in earlier and pre-release (beta) Microsoft Office formats.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Dif and Sylk files" is set to "Enabled: Open/Save blocked, use open policy".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\excel\\security\\fileblock

Criteria: If the value DifandSylkFiles is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2013 -> Excel Options -> Security -> Trust Center -> File Block Settings "Dif and Sylk files" to "Enabled: Open/Save blocked, use open policy".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2013'
  tag check_id: 'C-47752r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26596'
  tag rid: 'SV-53620r1_rule'
  tag stig_id: 'DTOO112'
  tag gtitle: 'DTOO112 - Dif and Sylk files'
  tag fix_id: 'F-46546r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
