control 'SV-228429' do
  title 'Publishing calendars to Office Online must be prevented.'
  desc 'This policy setting controls whether Outlook users can publish their calendars to the Office.com Calendar Sharing Service. If you enable this policy setting, Outlook users cannot publish their calendars to Office.com. If you disable do not configure this policy setting, Outlook users can share their calendars with selected others by publishing them to the Microsoft Outlook Calendar Sharing Service. Users can control who can view their calendar and at what level of detail.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to Office.com" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\pubcal

Criteria: If the value DisableOfficeOnline is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Outlook Options -> Preferences -> Calendar Options -> Office.com Sharing Service "Prevent publishing to Office.com" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30662r497609_chk'
  tag severity: 'medium'
  tag gid: 'V-228429'
  tag rid: 'SV-228429r508021_rule'
  tag stig_id: 'DTOO216'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30647r497610_fix'
  tag 'documentable'
  tag legacy: ['SV-85753', 'V-71129']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
