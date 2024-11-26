control 'SV-252881' do
  title 'Firefox must be configured to not delete data upon shutdown.'
  desc 'For diagnostic purposes, data must remain behind when the browser is closed. This is required to meet non-repudiation controls.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "SanitizeOnShutdown" is not displayed under Policy Name or the Policy Value does not have {"Cache":false,"Cookies":false,"Downloads":false,"FormData":false,"Sessions":false,"History":false,"OfflineApps":false,"SiteSettings":false,"Locked":true}, this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Clear data when browser is closed
Policy Name: Cache, Cookies, Download History, Form & Search History, Browsing History, Active Logins, Site Preferences, Offline Website Data
Policy State: Disabled
Policy Name: Locked
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>SanitizeOnShutdown</key>
<dict>
  <key>Cache</key>
  <false/>
  <key>Cookies</key>
  <false/>
  <key>Downloads</key>
  <false/>
  <key>FormData</key>
  <false/>
  <key>History</key>
  <false/>
  <key>Sessions</key>
  <false/>
  <key>SiteSettings</key>
  <false/>
  <key>OfflineApps</key>
  <false/>
  <key>Locked</key>
  <true/>
</dict>

Linux "policies.json" file:
Add the following in the policies section:
"SanitizeOnShutdown": {
  "Cache": false,
  "Cookies": false,
  "Downloads": false,
  "FormData": false,
  "History": false,
  "Sessions": false,
  "SiteSettings": false,
  "OfflineApps": false,
  "Locked": true 
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-56337r820755_chk'
  tag severity: 'medium'
  tag gid: 'V-252881'
  tag rid: 'SV-252881r820757_rule'
  tag stig_id: 'FFOX-00-000017'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-56287r820756_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
