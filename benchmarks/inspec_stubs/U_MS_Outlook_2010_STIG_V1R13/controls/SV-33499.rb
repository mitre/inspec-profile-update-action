control 'SV-33499' do
  title 'Do not include Internet Calendar Integration in Outlook must be enforced.'
  desc 'The Internet Calendar feature in Outlook enables users to publish calendars online (using the webcal:// protocol) and subscribe to calendars that others have published. When users subscribe to an Internet calendar, Outlook queries the calendar at regular intervals and downloads any changes as they are posted.
By default, Outlook allows users to subscribe to Internet calendars. If your organization has policies that govern the use of external resources such as Internet calendars, this feature might enable users to violate those policies.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Internet Calendars “Do not include Internet Calendar integration in Outlook” must be set to “Enabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\webcal

Criteria: If the value Disable is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> Internet Calendars “Do not include Internet Calendar integration in Outlook”  to “Enabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33982r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17678'
  tag rid: 'SV-33499r1_rule'
  tag stig_id: 'DTOO285 - Outlook'
  tag gtitle: 'DTOO285 - Internet Calendar Integration'
  tag fix_id: 'F-29671r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
