control 'SV-251567' do
  title 'Firefox fingerprinting protection must be enabled.'
  desc 'The Content Blocking/Tracking Protection feature stops Firefox from loading content from malicious sites. The content might be a script or an image, for example. If a site is on one of the tracker lists that Firefox is set to use, the fingerprinting script (or other tracking script/image) will not be loaded from that site.

Fingerprinting scripts collect information about browser and device configuration, such as operating system, screen resolution, and other settings. By compiling these pieces of data, fingerprinters create a unique profile that can be used to track the user around the web.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "EnableTrackingProtection" is not displayed under Policy Name or the Policy Value is not "Fingerprinting"  with a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Tracking Protection
Policy Name: Fingerprinting
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>EnableTrackingProtection</key>
  <dict>
    <key>Fingerprinting</key>
 <true/>
  </dict>

Linux "policies.json" file:
Add the following in the policies section:
"EnableTrackingProtection": {
  "Fingerprinting": true
}'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55002r807171_chk'
  tag severity: 'medium'
  tag gid: 'V-251567'
  tag rid: 'SV-251567r807173_rule'
  tag stig_id: 'FFOX-00-000023'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54956r807172_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
