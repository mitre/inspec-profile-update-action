control 'SV-228468' do
  title 'Disabling download full text of articles as HTML must be configured.'
  desc 'This policy setting controls whether Outlook automatically makes an offline copy of the RSS items as HTML attachments. If you enable this policy setting, Outlook automatically makes an offline copy of RSS items as HTML attachments. If you disable or do not configure this policy setting, Outlook will not automatically make an offline copy of RSS items as HTML attachments.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> RSS Feeds "Download full text of articles as HTML attachments" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\16.0\\outlook\\options\\rss

Criteria: If the value EnableFullTextHTML is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2016 -> Account Settings -> RSS Feeds "Download full text of articles as HTML attachments" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2016'
  tag check_id: 'C-30701r497726_chk'
  tag severity: 'medium'
  tag gid: 'V-228468'
  tag rid: 'SV-228468r508021_rule'
  tag stig_id: 'DTOO283'
  tag gtitle: 'SRG-APP-000516'
  tag fix_id: 'F-30686r497727_fix'
  tag 'documentable'
  tag legacy: ['SV-85883', 'V-71259']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
