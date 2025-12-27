control 'SV-252908' do
  title 'Pocket must be disabled.'
  desc 'Pocket, previously known as Read It Later, is a social bookmarking service for storing, sharing, and discovering web bookmarks. Data gathering cloud services such as this are generally disabled in the DoD.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "DisablePocket" is not displayed under Policy Name or the Policy Value does not have a value of "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Pocket
Policy State: Enabled

macOS "plist" file:
<key>DisablePocket</key>
 <true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisablePocket": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-56361r836394_chk'
  tag severity: 'medium'
  tag gid: 'V-252908'
  tag rid: 'SV-252908r879587_rule'
  tag stig_id: 'FFOX-00-000038'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-56311r832309_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
