control 'SV-223310' do
  title 'Trusted Locations on the network must be disabled in Excel.'
  desc 'This policy setting controls whether trusted locations on the network can be used.

If you enable this policy setting, users can specify trusted locations on network shares or in other remote locations that are not under their direct control by selecting the "Allow Trusted Locations on my network (not recommended)" check box in the Trusted Locations section of the Trust Center. Content, code, and add-ins are allowed to load from trusted locations with minimal security and without prompting the user for permission.

If you disable or do not configure this policy setting, the selected application ignores any network locations listed in the Trusted Locations section of the Trust Center. Disabling this policy setting does not delete any network locations from the Trusted Locations list. Instead, it forces the selected application to treat the locations as non-trusted and prevents users from adding new network locations to the list.

If you also deploy Trusted Locations via Group Policy, you should verify whether any of them are remote locations. If any of them are remote locations and you do not allow remote locations via this policy setting, those policy keys that point to remote locations will be ignored on client computers.

Disabling this policy setting will cause disruption for users who add network locations to the Trusted Locations list. However, it is not recommended to enable this policy setting (as the "Allow Trusted Locations on my network (not recommended)" check box itself states), so in practice it should be possible to disable this policy setting in most situations without causing significant usability issues for most users.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Trusted Locations "Allow Trusted Locations on the network" is set to "Disabled".

Use the Windows Registry Editor to navigate to the following key:

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\excel\\security\\trusted locations

If the value AllowNetworkLocations is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Excel 2016 >> Excel Options >> Security >> Trust Center >> Trusted Locations "Allow Trusted Locations on the network" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Office 365 ProPlus'
  tag check_id: 'C-24983r442149_chk'
  tag severity: 'medium'
  tag gid: 'V-223310'
  tag rid: 'SV-223310r879630_rule'
  tag stig_id: 'O365-EX-000001'
  tag gtitle: 'SRG-APP-000210'
  tag fix_id: 'F-24971r442150_fix'
  tag 'documentable'
  tag legacy: ['SV-108799', 'V-99695']
  tag cci: ['CCI-001170']
  tag nist: ['SC-18 (4)']
end
