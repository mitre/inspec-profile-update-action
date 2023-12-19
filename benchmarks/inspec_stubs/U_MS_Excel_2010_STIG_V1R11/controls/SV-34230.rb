control 'SV-34230' do
  title 'Open/Save actions for dBase III / IV files must be blocked.'
  desc 'This policy setting allows for determining whether users can open, view, edit, or save Excel files with the format specified by the title.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “dBase III / IV files” must be “Enabled: Open/Save blocked, use open policy".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\excel\\security\\fileblock

Criteria: If the value DBaseFiles is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Excel 2010 -> Excel Options -> Security -> Trust Center -> File Block Settings “dBase III / IV files” to “Enabled: Open/Save blocked, use open policy".'
  impact 0.5
  ref 'DPMS Target Microsoft Excel 2010'
  tag check_id: 'C-34194r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26595'
  tag rid: 'SV-34230r1_rule'
  tag stig_id: 'DTOO122 - Excel'
  tag gtitle: 'DTOO122 - dBase III / IV files'
  tag fix_id: 'F-29888r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
