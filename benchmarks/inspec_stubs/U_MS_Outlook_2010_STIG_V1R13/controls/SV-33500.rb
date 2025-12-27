control 'SV-33500' do
  title 'Disabling download full text of articles as HTML must be configured.'
  desc 'Many RSS feeds use messages that contain a brief summary of a larger message or an article with a link to the full content. Users can configure Outlook to automatically download the linked content as message attachments for individual RSS feeds. If a feed is frequently updated or typically contains very large messages and is not AutoArchived regularly, downloading full articles can cause the affected message store to become very large, which can affect the performance of Outlook.
By default, Outlook does not automatically download the full text of RSS entries when retrieving feeds.'
  desc 'check', 'The policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Download full text of articles as HTML attachments” must be set to “Disabled”.

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\14.0\\outlook\\options\\rss

Criteria: If the value EnableFullTextHTML is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2010 -> Account Settings -> RSS Feeds “Download full text of articles as HTML attachments” to “Disabled”.'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2010'
  tag check_id: 'C-33983r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17610'
  tag rid: 'SV-33500r1_rule'
  tag stig_id: 'DTOO283 - Outlook'
  tag gtitle: 'DTOO283 - Dwnld articles as HTML attachments'
  tag fix_id: 'F-29672r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
end
