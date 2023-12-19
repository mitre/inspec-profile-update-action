control 'SV-53871' do
  title 'Level of calendar details that a user can publish must be restricted.'
  desc "Outlook users can share their calendars with selected others by publishing them to the Microsoft Office Outlook Calendar Sharing Service. Users can choose from three levels of detail:
* Availability only. Authorized visitors will see the user's time marked as Free, Busy, tentative, or Out of Office, but will not be able to see the subjects or details of calendar items.
* Limited details. Authorized visitors can see the user's availability and the subjects of calendar items only. They will not be able to view the details of calendar items. Optionally, users can allow visitors to see the existence of private items.
* Full details. Authorized visitors can see the full details of calendar items. Optionally, users can allow visitors to see the existence of private items and to access attachments within calendar items.
If users are allowed to publish limited or full details, sensitive information in their calendars could become exposed to parties who are not authorized to have that information."
  desc 'check', %q(Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Restrict level of calendar details users can publish" is "Enabled (Disables 'Full details' and 'Limited details')".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\Software\Policies\Microsoft\Office\15.0\outlook\options\pubcal

Criteria: If the value PublishCalendarDetailsPolicy is REG_DWORD = 4000 (hex) or 16384 (Decimal), this is not a finding.)
  desc 'fix', %q(Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Restrict level of calendar details users can publish" to "Enabled (Disables 'Full details' and 'Limited details')".)
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47912r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17776'
  tag rid: 'SV-53871r1_rule'
  tag stig_id: 'DTOO218'
  tag gtitle: 'DTOO218 - Calendar details published by users'
  tag fix_id: 'F-46776r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
