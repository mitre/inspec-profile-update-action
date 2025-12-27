control 'SV-251564' do
  title 'Firefox search suggestions must be disabled.'
  desc 'Search suggestions must be disabled as this could lead to searches being conducted that were never intended to be made.'
  desc 'check', 'Type "about:policies" in the browser window.

If "SearchSuggestEnabled" is not displayed under Policy Name or the Policy Value is not "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Search
Policy Name: Search Suggestions
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>SearchSuggestEnabled</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"SearchSuggestEnabled": false'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54999r807162_chk'
  tag severity: 'medium'
  tag gid: 'V-251564'
  tag rid: 'SV-251564r807164_rule'
  tag stig_id: 'FFOX-00-000020'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54953r807163_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
