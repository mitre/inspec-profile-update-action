control 'SV-228472' do
  title 'Automatically downloading enclosures on RSS must be disallowed.'
  desc 'This policy setting allows you to control whether Outlook automatically downloads enclosures on RSS items. If you enable this policy setting, Outlook will automatically download enclosures on RSS items. If you disable or do not configure this policy setting, enclosures on RSS items are not downloaded by default.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> RSS Feeds "Automatically download enclosures" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\rss

Criteria: If the value EnableAttachments is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> RSS Feeds "Automatically download enclosures" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30705r497738_chk'
  tag severity: 'medium'
  tag gid: 'V-228472'
  tag rid: 'SV-228472r508021_rule'
  tag stig_id: 'DTOO313'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-30690r497739_fix'
  tag 'documentable'
  tag legacy: ['SV-85891', 'V-71267']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
