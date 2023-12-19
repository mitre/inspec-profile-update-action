control 'SV-223394' do
  title 'Trusted Locations on the network must be disabled in Visio.'
  desc 'This policy setting controls whether trusted locations on the network can be used.

If you enable this policy setting, users can specify trusted locations on network shares or in other remote locations that are not under their direct control by clicking the "Add new location" button in the Trusted Locations section of the Trust Center. Content, code, and add-ins are allowed to load from trusted locations with minimal security and without prompting the user for permission.

If you disable this policy setting, the selected application ignores any network locations listed in the Trusted Locations section of the Trust Center. 

If you also deploy Trusted Locations via Group Policy, you should verify whether any of them are remote locations. If any of them are remote locations and you do not allow remote locations via this policy setting, those policy keys that point to remote locations will be ignored on client computers.

Disabling this policy setting does not delete any network locations from the Trusted Locations list, but causes disruption for users who add network locations to the Trusted Locations list. Users are also prevented from adding new network locations to the Trusted Locations list in the Trust Center. We recommended that you do not enable this policy setting as the "Allow Trusted Locations on my network (not recommended)" check box also states. Therefore, in practice, it should be possible to disable this policy setting in most situations without causing significant usability issues for most users.

If you do not enable this policy setting, users can select the "Allow Trusted Locations on my network (not recommended)" check box if desired and then specify trusted locations by clicking the "Add new location" button.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> Allow Trusted Locations on the network is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\software\\policies\\microsoft\\office\\16.0\\visio\\security\\trusted locations

If the value for allownetworklocations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Visio 2016 >> Visio Options >> Security >> Trust Center >> Allow Trusted Locations on the network to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25067r442401_chk'
  tag severity: 'medium'
  tag gid: 'V-223394'
  tag rid: 'SV-223394r879630_rule'
  tag stig_id: 'O365-VI-000002'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25055r442402_fix'
  tag 'documentable'
  tag legacy: ['SV-108969', 'V-99865']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
