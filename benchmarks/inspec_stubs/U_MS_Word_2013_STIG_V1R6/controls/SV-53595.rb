control 'SV-53595' do
  title 'Word 97 binary documents and templates must be configured to edit in protected view.'
  desc 'This setting specifies whether users can open, view, edit, or save files saved in the specified format. Enabling the editing of the specified format in protected view, it mitigates zero-day security attacks (which are attacks that occur during between the time that a vulnerability becomes publicly known and a software update or service pack is available) by temporarily preventing users from opening specific types of files and to prevent a user from opening files that have been saved in earlier and pre-release (beta) Microsoft Office formats.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> File Block Settings "Word 97 binary documents and templates" is set to "Enabled: Allow editing and open in Protected View".   

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\security\\fileblock

Criteria: If the value Word97Files is REG_DWORD = 5, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> File Block Settings "Word 97 binary documents and templates" to "Enabled: Allow editing and open in Protected View".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47741r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26658'
  tag rid: 'SV-53595r1_rule'
  tag stig_id: 'DTOO338'
  tag gtitle: 'DTOO338 -  Word 97 binary documents and templates'
  tag fix_id: 'F-46520r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
