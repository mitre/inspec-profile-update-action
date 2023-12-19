control 'SV-34096' do
  title 'Word 2000 binary documents and templates must be configured to edit in protected view.'
  desc 'This setting allows you to determine whether users can open, view, edit, or save Word files with the format specified by the title of this policy setting.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Word 2000 binary documents and templates” must be “Enabled: Allow editing and open in Protected View".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\fileblock

Criteria: If the value Word2000Files is REG_DWORD = 5, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Word 2000 binary documents and templates” to “Enabled: Allow editing and open in Protected View".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34254r2_chk'
  tag severity: 'medium'
  tag gid: 'V-26654'
  tag rid: 'SV-34096r2_rule'
  tag stig_id: 'DTOO334 - Word'
  tag gtitle: 'DTOO334 - Word 2000 binary documents and templates'
  tag fix_id: 'F-29948r2_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
