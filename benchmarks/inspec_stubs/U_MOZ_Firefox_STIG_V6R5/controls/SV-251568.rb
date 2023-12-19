control 'SV-251568' do
  title 'Firefox cryptomining protection must be enabled.'
  desc "The Content Blocking/Tracking Protection feature stops Firefox from loading content from malicious sites. The content might be a script or an image, for example. If a site is on one of the tracker lists that Firefox is set to use, the fingerprinting script (or other tracking script/image) will not be loaded from that site.

Cryptomining scripts use a computer's central processing unit to invisibly mine cryptocurrency."
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "EnableTrackingProtection" is not displayed under Policy Name or the Policy Value is not "Cryptomining" with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Tracking Protection
Policy Name: Cryptomining
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>EnableTrackingProtection</key>
  <dict>
    <key>Cryptomining</key>
 <true/>
  </dict>

Linux "policies.json" file:
Add the following in the policies section:
"EnableTrackingProtection": {
  "Cryptomining": true
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55003r807174_chk'
  tag severity: 'medium'
  tag gid: 'V-251568'
  tag rid: 'SV-251568r879587_rule'
  tag stig_id: 'FFOX-00-000024'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54957r807175_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
