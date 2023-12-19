control 'SV-54054' do
  title 'RSS feed synchronization with Common Feed List must be disallowed.'
  desc 'The Common Feed list is a hierarchical set of RSS feeds to which clients such as Outlook 2013, the Feeds list in Internet Explorer, and the Feed Headlines Sidebar gadget in Windows Vista can subscribe.
If Outlook subscribes to a very large feed list, performance and availability can be affected, especially if Outlook is configured to download full RSS message bodies or if the feed list is not AutoArchived regularly.  By default, Outlook maintains its own list of feeds and does not automatically subscribe to RSS feeds that are added to the Common Feed List.'
  desc 'check', 'Verify the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> RSS Feeds "Synchronize Outlook RSS Feeds with Common Feed List" is set to "Disabled".

Procedure: Use the Windows Registry Editor to navigate to the following key: 

HKCU\\Software\\Policies\\Microsoft\\Office\\15.0\\outlook\\options\\rss

Criteria: If the value SyncToSysCFL is REG_DWORD = 0, this is not a finding.'
  desc 'fix', 'Set the policy value for User Configuration -> Administrative Templates -> Microsoft Outlook 2013 -> Account Settings -> RSS Feeds "Synchronize Outlook RSS Feeds with Common Feed List" to "Disabled".'
  impact 0.5
  ref 'DPMS Target Microsoft Outlook 2013'
  tag check_id: 'C-47994r1_chk'
  tag severity: 'medium'
  tag gid: 'V-17806'
  tag rid: 'SV-54054r1_rule'
  tag stig_id: 'DTOO281'
  tag gtitle: 'DTOO281 - Sync RSS Feeds w/Common List'
  tag fix_id: 'F-46934r1_fix'
  tag 'documentable'
  tag responsibility: ['System Administrator', 'Information Assurance Officer']
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
