control 'SV-228431' do
  title 'Level of calendar details that a user can publish must be restricted.'
  desc "This policy setting controls the level of calendar details that Outlook users can publish to the Microsoft Outlook Calendar Sharing Service. If you enable this policy setting, you can choose from three levels of detail: * All options are available - This level of detail is the default configuration. * Disables 'Full details' * Disables 'Full details' and 'Limited details'. If you disable or do not configure this policy setting, Outlook users can share their calendars with selected others by publishing them to the Microsoft Outlook Calendar Sharing Service. Users can choose from three levels of detail: * Availability only - Authorized visitors will see the user's time marked as Free, Busy, Tentative, or Out of Office, but will not be able to see the subjects or details of calendar items. * Limited details - Authorized visitors can see the user's availability and the subjects of calendar items only. They will not be able to view the details of calendar items. Optionally, users can allow visitors to see the existence of private items. * Full details - Authorized visitors can see the full details of calendar items. Optionally, users can allow visitors to see the existence of private items."
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Restrict level of calendar details users can publish" is set to "Enabled (Disables 'Full details' and 'Limited details')".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\16.0\outlook\options\pubcal

Criteria: If the value PublishCalendarDetailsPolicy is REG_DWORD = 4000 (hex) or 16384 (Decimal), this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Restrict level of calendar details users can publish" to "Enabled (Disables 'Full details' and 'Limited details')".)
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30664r497615_chk'
  tag severity: 'medium'
  tag gid: 'V-228431'
  tag rid: 'SV-228431r508021_rule'
  tag stig_id: 'DTOO218'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30649r497828_fix'
  tag 'documentable'
  tag legacy: ['SV-85757', 'V-71133']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
