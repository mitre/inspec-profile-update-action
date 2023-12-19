control 'SV-228469' do
  title 'Automatic download of Internet Calendar appointment attachments must be disallowed.'
  desc 'This policy setting controls whether Outlook downloads files attached to Internet Calendar appointments. If you enable this policy setting, Outlook automatically downloads all Internet Calendar appointment attachments. If you disable or do not configure this policy setting, Outlook does not download attachments when retrieving Internet Calendar appointments.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Internet Calendars "Automatically download attachments" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\webcal

Criteria: If the value EnableAttachments is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> Internet Calendars "Automatically download attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30702r497729_chk'
  tag severity: 'medium'
  tag gid: 'V-228469'
  tag rid: 'SV-228469r508021_rule'
  tag stig_id: 'DTOO284'
  tag gtitle: 'SRG-APP-000209'
  tag fix_id: 'F-30687r497730_fix'
  tag 'documentable'
  tag legacy: ['SV-85885', 'V-71261']
  tag cci: ['CCI-001169']
  tag nist: ['SC-18 (3)']
end
