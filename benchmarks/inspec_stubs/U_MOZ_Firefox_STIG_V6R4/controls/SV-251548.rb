control 'SV-251548' do
  title 'Firefox must be configured to not automatically check for updated versions of installed search plugins.'
  desc 'Updates must be controlled and installed from authorized and trusted servers. This setting overrides a number of other settings that may direct the application to access external URLs.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "browser.search.update" is not displayed with a value of "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "browser.search.update": {
    "Value": false,
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>browser.search.update</key>
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
  "browser.search.update": {
    "Value": false,
    "Status": "locked"
  }
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54983r807114_chk'
  tag severity: 'medium'
  tag gid: 'V-251548'
  tag rid: 'SV-251548r807116_rule'
  tag stig_id: 'FFOX-00-000004'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54937r807115_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
