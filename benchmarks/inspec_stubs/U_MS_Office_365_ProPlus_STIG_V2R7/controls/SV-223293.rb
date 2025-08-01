control 'SV-223293' do
  title 'Users must be prevented from creating new trusted locations in the Trust Center.'
  desc 'This policy setting controls whether trusted locations can be defined by users, the Office Customization Tool (OCT), and Group Policy, or if they must be defined by Group Policy alone.

If you enable this policy setting, users can specify any location as a trusted location, and a computer can have a combination of user-created, OCT-created, and Group Policy-created trusted locations.

If you disable this policy setting, all trusted locations that are not created by Group Policy are disabled and users cannot create new trusted locations in the Trust Center.

If you do not configure this policy setting, the behavior is the equivalent of setting the policy to Enabled.

Note: InfoPath and Outlook do not recognize trusted locations, and therefore are unaffected by this policy setting.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016\\Security Settings\\Trust Center >> Allow mix of policy and user locations is set to "Disabled".
 
Use the Windows Registry Editor to navigate to the following key: 

HKCU\\software\\policies\\microsoft\\office\\16.0\\common\\security\\trusted locations

If the value for allow user locations is set to REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Office 2016 >> Security Settings >> Trust Center >> Allow mix of policy and user locations to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24966r442098_chk'
  tag severity: 'medium'
  tag gid: 'V-223293'
  tag rid: 'SV-223293r850628_rule'
  tag stig_id: 'O365-CO-000010'
  tag gtitle: 'SRG-APP-000340'
  tag fix_id: 'F-24954r442099_fix'
  tag 'documentable'
  tag legacy: ['SV-108763', 'V-99659']
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
