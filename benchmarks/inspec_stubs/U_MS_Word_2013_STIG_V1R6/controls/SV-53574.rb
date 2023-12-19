control 'SV-53574' do
  title 'The Save commands default file format must be configured.'
  desc 'When users create new document files, Word 2013 saves them in the new Word 2013 .docx format.  Ensure this setting is enabled to specify that all new files are created in Word 2013.  If a new document is created in an earlier format, some users may not be able to open or use the file, or they may choose a format this is less secure than the Word 2013 format.  Users can still select a specific format when they save files, but they cannot change default of this setting from the Word Options dialog box.  This enforced user behavior ensures any change to the file format requires additional deliberate user interaction.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Save "default file format" is set to "Enabled Word Document (.docx)". 

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\word\\options 

Criteria: If the value DefaultFormat is REG_SZ = (blank), this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Word 2013 -> Word Options -> Save "default file format" to "Enabled Word Document (.docx)".'
  impact 0.5
  ref 'DPMS Target Microsoft Word 2013'
  tag check_id: 'C-47722r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17521'
  tag rid: 'SV-53574r1_rule'
  tag stig_id: 'DTOO139'
  tag gtitle: 'DTOO139 - Save files default format'
  tag fix_id: 'F-46498r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
