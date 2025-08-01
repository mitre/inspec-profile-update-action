control 'SV-251547' do
  title 'Firefox must be configured to ask which certificate to present to a website when a certificate is required.'
  desc 'When a website asks for a certificate for user authentication, Firefox must be configured to have the user choose which certificate to present. Websites within DoD require user authentication for access, which increases security for DoD information. Access will be denied to the user if certificate management is not configured.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "security.default_personal_cert" is not displayed with a value of "Ask Every Time", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\
Policy Name: Preferences
Policy State: Enabled
Policy Value:
{
  "security.default_personal_cert": {
    "Value": "Ask Every Time",
    "Status": "locked"
  }
}

macOS "plist" file:
Add the following:
<key>Preferences</key>
<dict>
  <key>security.default_personal_cert</key>
  <dict>
    <key>Value</key>
    <string>Ask Every Time</string>
    <key>Status</key>
    <string>locked</string>
  </dict>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"Preferences": {
  "security.default_personal_cert": {
    "Value": "Ask Every Time",
    "Status": "locked"
  }
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54982r807111_chk'
  tag severity: 'medium'
  tag gid: 'V-251547'
  tag rid: 'SV-251547r807113_rule'
  tag stig_id: 'FFOX-00-000003'
  tag gtitle: 'SRG-APP-000177'
  tag fix_id: 'F-54936r807112_fix'
  tag 'documentable'
  tag cci: ['CCI-000187']
  tag nist: ['IA-5 (2) (a) (2)']
end
