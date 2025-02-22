control 'SV-251555' do
  title 'Firefox must be configured to prevent JavaScript from raising or lowering windows.'
  desc 'JavaScript can raise and lower browser windows to cause improper input. Configure the browser setting to prevent scripts on visited websites from raising and lowering browser windows.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "dom.disable_window_flip" is not displayed with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "dom.disable_window_flip": {
    "Value": true,
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>dom.disable_window_flip</key>
  <dict>
    <key>Value</key>
    <true/>
    <key>Status</key>
    <string>locked</string>
  </dict>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"Preferences": {
  "dom.disable_window_flip": {
    "Value": true,
    "Status": "locked"
  }
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54990r807135_chk'
  tag severity: 'medium'
  tag gid: 'V-251555'
  tag rid: 'SV-251555r807137_rule'
  tag stig_id: 'FFOX-00-000011'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54944r807136_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
