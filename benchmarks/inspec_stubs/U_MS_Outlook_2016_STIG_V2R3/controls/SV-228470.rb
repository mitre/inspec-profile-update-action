control 'SV-228470' do
  title 'Internet calendar integration in Outlook must be disabled.'
  desc 'This policy setting allows the user to determine whether or not to include Internet Calendar integration in Outlook. The Internet Calendar feature in Outlook enables users to publish calendars online (using the webcal:// protocol) and subscribe to calendars that others have published. When users subscribe to an internet calendar, Outlook queries the calendar at regular intervals and downloads any changes as they are posted. If this policy setting is enabled, all internet calendar functionality in Outlook is disabled. If this policy setting  is disabled or not configured, Outlook allows users to subscribe to trusted and untrusted internet calendars. The webcal protocol also has a history of loading web sites vulnerable to cross site scripting.'
  desc 'check', 'Verify the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Internet Calendars "Do not include Internet Calendar integration in Outlook" is set to "Enabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\webcal

Criteria: If the value Disable is REG_DWORD = 1, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration >> Administrative Templates >> Microsoft Outlook 2016 >> Account Settings >> Internet Calendars "Do not include Internet Calendar integration in Outlook" to "Enabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30703r822349_chk'
  tag severity: 'medium'
  tag gid: 'V-228470'
  tag rid: 'SV-228470r822351_rule'
  tag stig_id: 'DTOO285'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30688r822350_fix'
  tag 'documentable'
  tag legacy: ['SV-85887', 'V-71263']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
