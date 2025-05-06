control 'SV-34097' do
  title 'Word 6.0 binary documents and templates must be configured for block open/save actions.'
  desc 'This setting allows you to determine whether users can open, view, edit, or save Word files with the format specified by the title of this policy setting.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Word 6.0 binary documents and templates” must be “Enabled: Open/Save blocked, use open policy”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\word\\security\\fileblock

Criteria: If the value Word60Files is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2010 -> Word Options -> Security -> Trust Center -> File Block Settings “Word 6.0 binary documents and templates” to “Enabled: Open/Save blocked, use open policy”.'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2010'
  tag check_id: 'C-34255r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26656'
  tag rid: 'SV-34097r1_rule'
  tag stig_id: 'DTOO336 - Word'
  tag gtitle: 'DTOO336 - Word 6.0 binary documents and templates'
  tag fix_id: 'F-29949r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
