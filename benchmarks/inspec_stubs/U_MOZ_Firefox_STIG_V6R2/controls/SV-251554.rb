control 'SV-251554' do
  title 'Firefox must be configured to prevent JavaScript from moving or resizing windows.'
  desc "JavaScript can make changes to the browser's appearance. This activity can help disguise an attack taking place in a minimized background window. Configure the browser setting to prevent scripts on visited websites from moving and resizing browser windows."
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "dom.disable_window_move_resize" is not displayed with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "dom.disable_window_move_resize": {
    "Value": true,
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>dom.disable_window_move_resize</key>
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
  "dom.disable_window_move_resize": {
    "Value": true,
    "Status": "locked"
  }
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54989r807132_chk'
  tag severity: 'medium'
  tag gid: 'V-251554'
  tag rid: 'SV-251554r807134_rule'
  tag stig_id: 'FFOX-00-000010'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54943r807133_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
