control 'SV-251570' do
  title 'Firefox extension recommendations must be disabled.'
  desc 'The Recommended Extensions program makes it easier for users to discover extensions that have been reviewed for security, functionality, and user experience. Allowed extensions are to be centrally managed.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "extensions.htmlaboutaddons.recommendations.enabled" is not displayed with a value of "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "extensions.htmlaboutaddons.recommendations.enabled": {
    "Value": false,
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>extensions.htmlaboutaddons.recommendations.enabled</key>
  <dict>
    <key>Value</key>
    <false/>
    <key>Status</key>
    <string>locked</string>
  </dict>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"Preferences": {
"extensions.htmlaboutaddons.recommendations.enabled": {
"Value": false,
"Status": "locked"
},'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55005r807180_chk'
  tag severity: 'medium'
  tag gid: 'V-251570'
  tag rid: 'SV-251570r879587_rule'
  tag stig_id: 'FFOX-00-000026'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54959r820758_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
