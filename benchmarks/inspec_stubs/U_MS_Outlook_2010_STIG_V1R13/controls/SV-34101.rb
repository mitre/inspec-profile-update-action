control 'SV-34101' do
  title 'Automatically downloading enclosures on RSS must be disallowed.'
  desc 'This policy setting allows you to control whether Outlook automatically downloads enclosures on RSS items.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Automatically download enclosures” must be set to “Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\rss

Criteria: If the value EnableAttachments is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Automatically download enclosures” to “Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-34228r1_chk'
  tag severity: 'medium'
  tag gid: 'V-26632'
  tag rid: 'SV-34101r1_rule'
  tag stig_id: 'DTOO313 - Outlook'
  tag gtitle: 'DTOO313 - Automatically download enclosures'
  tag fix_id: 'F-29918r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
