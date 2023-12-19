control 'SV-238033' do
  title 'A mix of policy and user locations for Office Products must be disallowed.'
  desc 'This policy setting controls whether trusted locations can be defined by users, the Office Customization Tool (OCT), and Group Policy, or if they must be defined by Group Policy alone. If you enable this policy setting, users can specify any location as a trusted location, and a computer can have a combination of user-created, OCT-created, and Group Policy-created trusted locations. If you disable this policy setting, all trusted locations that are not created by Group Policy are disabled and users cannot create new trusted locations in the Trust Center. If you do not configure this policy setting, the behavior is the equivalent of setting the policy to Enabled. Note -  InfoPath 2016 and Outlook 2016 do not recognize trusted locations, and therefore are unaffected by this policy setting.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings -> Trust Center "Allow mix of policy and user locations" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 


HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\common\\security\\trusted locations

Criteria: If the value Allow User Locations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Office 2016 -> Security Settings -> Trust Center "Allow mix of policy and user locations" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office System 2016'
  tag check_id: 'C-41243r650664_chk'
  tag severity: 'medium'
  tag gid: 'V-238033'
  tag rid: 'SV-238033r650666_rule'
  tag stig_id: 'DTOO196'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-41202r650665_fix'
  tag 'documentable'
  tag legacy: ['SV-85499', 'V-70875']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
