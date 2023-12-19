control 'SV-223389' do
  title 'The use of network locations must be ignored in PowerPoint.'
  desc 'This policy setting controls whether trusted locations on the network can be used. If you enable this policy setting, users can specify trusted locations on network shares or in other remote locations that are not under their direct control by clicking the "Add new location" button in the Trusted Locations section of the Trust Center. Content, code, and add-ins are allowed to load from trusted locations with minimal security and without prompting the user for permission. 

If you disable this policy setting, the selected application ignores any network locations listed in the Trusted Locations section of the Trust Center. If you also deploy Trusted Locations via Group Policy, you should verify whether any of them are remote locations. If any of them are remote locations and you do not allow remote locations via this policy setting, those policy keys that point to remote locations will be ignored on client computers. 

Disabling this policy setting does not delete any network locations from the Trusted Locations list, but causes disruption for users who add network locations to the Trusted Locations list. Users are also prevented from adding new network locations to the Trusted Locations list in the Trust Center. It is recommended that you do not enable this policy setting, as the "Allow Trusted Locations on my network (not recommended) check box also states. Therefore, in practice, it should be possible to disable this policy setting in most situations without causing significant usability issues for most users. If you do not enable this policy setting, users can select the "Allow Trusted Locations on my network (not recommended)" check box if desired and then specify trusted locations by clicking the "Add new location" button.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Trusted Locations "Allow Trusted Locations on the network" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\PowerPoint\\security\\trusted locations

If the value AllowNetworkLocations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft PowerPoint 2016 >> PowerPoint Options >> Security >> Trust Center >> Trusted Locations "Allow Trusted Locations on the network" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-25062r442386_chk'
  tag severity: 'medium'
  tag gid: 'V-223389'
  tag rid: 'SV-223389r508019_rule'
  tag stig_id: 'O365-PT-000013'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-25050r442387_fix'
  tag 'documentable'
  tag legacy: ['SV-108953', 'V-99849']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
