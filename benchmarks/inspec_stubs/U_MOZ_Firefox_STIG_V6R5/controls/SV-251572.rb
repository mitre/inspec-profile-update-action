control 'SV-251572' do
  title 'Firefox must not recommend extensions as the user is using the browser.'
  desc 'The Recommended Extensions program recommends extensions to users as they surf the web.

The user must not be encouraged to install extensions from the websites they visit. Allowed extensions are to be centrally managed.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "UserMessaging" is not displayed under Policy Name or the Policy Value is not "ExtensionRecommendations" with a value of "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\User Messaging
Policy Name: Extension Recommendations
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>UserMessaging</key>
<dict>
  <key>ExtensionRecommendations</key>
  <false/>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"UserMessaging": {
  "ExtensionRecommendations": false
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55007r807186_chk'
  tag severity: 'medium'
  tag gid: 'V-251572'
  tag rid: 'SV-251572r879587_rule'
  tag stig_id: 'FFOX-00-000028'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54961r807187_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
