control 'SV-33470' do
  title 'A mix of policy and user locations for Office Products must be disallowed.'
  desc 'When Microsoft Office files are opened from trusted locations, all the content in the files is enabled and active. Users are not notified about any potential risks that might be contained in the files, such as unsigned macros, ActiveX controls, or links to content on the Internet.
By default, users can specify any location as a trusted location, and a computer can have a combination of user-created, OCT-created, and Group Policy–created trusted locations.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings -> Trust Center “Allow mix of policy and user locations” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 


HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\common\\security\\trusted locations

Criteria: If the value Allow User Locations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2010 -> Security Settings -> Trust Center “Allow mix of policy and user locations” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2010'
  tag check_id: 'C-33953r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17560'
  tag rid: 'SV-33470r1_rule'
  tag stig_id: 'DTOO196 - Office System'
  tag gtitle: 'DTOO196 - Mix of Policy and User Locations'
  tag fix_id: 'F-29642r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
