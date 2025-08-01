control 'SV-251565' do
  title 'Firefox autoplay must be disabled.'
  desc 'Autoplay allows the user to control whether videos can play automatically (without user consent) with audio content. The user must be able to select content that is run within the browser window.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "Permissions->Autoplay" is not displayed under Policy Name or the Policy Value is not "block-audio-video" with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Permissions\\Autoplay
Policy Name: Default autoplay level
Policy State: Enabled
Policy Value: Block Audio and Video

macOS "plist" file:
Add the following:
<key>Permissions</key>
<dict>
  <key>Autoplay</key>
  <dict>
    <string>block-audio-video</string>
  </dict>
</dict>
 
Linux "policies.json" file:
Add the following in the policies section:
"Permissions": {
  "Autoplay": {
    "Default": "block-audio-video"
  }
}'
  impact 0.3
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55000r807165_chk'
  tag severity: 'low'
  tag gid: 'V-251565'
  tag rid: 'SV-251565r807167_rule'
  tag stig_id: 'FFOX-00-000021'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54954r807166_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
