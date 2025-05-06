control 'SV-252909' do
  title 'Firefox Studies must be disabled.'
  desc "Studies try out different features and ideas before they are released to all Firefox users. Testing beta software is not in the DoD user's mission."
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "DisableFirefoxStudies" is not displayed under Policy Name or the Policy Value does not have a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Firefox Studies
Policy State: Enabled

macOS "plist" file:
<key>DisableFirefoxStudies</key>
 <true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableFirefoxStudies": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-56362r836407_chk'
  tag severity: 'medium'
  tag gid: 'V-252909'
  tag rid: 'SV-252909r836408_rule'
  tag stig_id: 'FFOX-00-000039'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-56312r832312_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
