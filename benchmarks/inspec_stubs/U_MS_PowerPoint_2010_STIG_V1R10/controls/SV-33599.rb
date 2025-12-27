control 'SV-33599' do
  title 'Save files default format  must be configured.'
  desc 'When users create new PowerPoint files, PowerPoint 2010 saves them in the new *.pptx format.  Ensure this setting is enabled to specify that all new files are created in PowerPoint 2010.  If a new file is created in an earlier format, some users may not be able to open or use the file, or they may choose a format this is less secure than the PowerPoint 2010 format.  Users can still select a specific format when they save files, but they cannot change default of this setting from the PowerPoint Options dialog box.  This enforced user behavior ensures any change to the file format requires additional deliberate user interaction.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Save “default file format” must be set to “Enabled PowerPoint Presentation (*.pptx)".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\powerpoint\\options 

Criteria: If the value DefaultFormat is REG_DWORD = 1b (hex) 27 (dec) , this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft PowerPoint 2010 -> PowerPoint Options -> Save “default file format” to “Enabled PowerPoint Presentation (*.pptx)".'
  impact 0.5
  ref 'DPMS Target Microsoft PowerPoint 2010'
  tag check_id: 'C-34063r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17521'
  tag rid: 'SV-33599r1_rule'
  tag stig_id: 'DTOO139 - PowerPoint'
  tag gtitle: 'DTOO139 - Save files default format'
  tag fix_id: 'F-29741r1_fix'
  tag 'documentable'
  tag responsibility: ['Information Assurance Officer', 'System Administrator']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
