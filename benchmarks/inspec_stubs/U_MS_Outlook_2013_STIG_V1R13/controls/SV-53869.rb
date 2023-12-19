control 'SV-53869' do
  title 'Publishing calendars to Office Online must be prevented.'
  desc 'Outlook users can share their calendars with selected others by publishing them to the Microsoft Office Outlook Calendar Sharing Service. Users can control who can view their calendar and at what level of detail. When an organization has policies that govern access to external resources such as Office Online, allowing users to publish their calendars will enable them to violate those policies.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to Office.com" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\pubcal

Criteria: If the value DisableOfficeOnline is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to Office.com" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47910r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17763'
  tag rid: 'SV-53869r1_rule'
  tag stig_id: 'DTOO216'
  tag gtitle: 'DTOO216 - Publishing to Office Online'
  tag fix_id: 'F-46774r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
