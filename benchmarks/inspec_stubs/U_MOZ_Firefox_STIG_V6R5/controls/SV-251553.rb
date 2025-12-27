control 'SV-251553' do
  title 'Firefox must be configured to block pop-up windows.'
  desc 'Pop-up windows may be used to launch an attack within a new browser window with altered settings. This setting blocks pop-up windows created while the page is loading.'
  desc 'check', 'Type "about:policies" in the browser address bar.

If "PopupBlocking" is not displayed under Policy Name or the Policy Value is not "Default" "true", this is a finding.
If "PopupBlocking" is not displayed under Policy Name or the Policy Value is not "Locked" "true", this is a finding.

"PopupBlocking" "Enabled" may be used to specify an allowlist of sites where pop-ups are desired, this is optional.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Popups
Policy Name: Block pop-ups from websites
Policy State: Enabled

Policy Name: Do not allow preferences to be changed
Policy State: Enabled

Optional:
Policy Name: Allowed Sites
Policy State: Enabled
Click "Show..." and enter a list of websites to be allowlisted.

macOS "plist" file:
Add the following:
<key>PopupBlocking</key>
  <dict>
    <key>Allow</key>
    <array>
      <string>http://example.mil</string>
      <string>http://example.gov</string>
    </array>
    <key>Default</key>
    <true/>
    <key>Locked</key>
    <true/>
  </dict>

Linux "policies.json" file:
Add the following in the policies section:
"PopupBlocking": {
      "Allow": ["http://example.mil/",
                "http://example.gov/"],
      "Default": true,
      "Locked": true}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54988r820748_chk'
  tag severity: 'medium'
  tag gid: 'V-251553'
  tag rid: 'SV-251553r879587_rule'
  tag stig_id: 'FFOX-00-000009'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54942r862957_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
