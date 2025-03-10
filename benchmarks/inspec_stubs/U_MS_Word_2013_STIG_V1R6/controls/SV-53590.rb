control 'SV-53590' do
  title 'Word 2 and earlier binary documents and templates must be blocked for open/save.'
  desc 'This setting specifies whether users can open, view, edit, or save Word files saved in the specified format. Enabling block of the specified format mitigates zero-day security attacks (which are attacks that occur during between the time that a vulnerability becomes publicly known and a software update or service pack is available) by temporarily preventing users from opening specific types of files and to prevent a user from opening files that have been saved in earlier and pre-release (beta) Microsoft Office formats.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> File Block Settings "Word 2 and earlier binary documents and templates" is set to "Enabled: Open/Save blocked, use open policy".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\security\\fileblock

Criteria: If the value Word2Files is REG_DWORD = 2, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Security -> Trust Center -> File Block Settings "Word 2 and earlier binary documents and templates" to "Enabled: Open/Save blocked, use open policy".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47736r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26653'
  tag rid: 'SV-53590r1_rule'
  tag stig_id: 'DTOO333'
  tag gtitle: 'DTOO333 - Word 2 and earlier binary documents'
  tag fix_id: 'F-46514r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-001662']
  tag nist: ['SC-18 (1)']
end
