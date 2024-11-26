control 'SV-251563' do
  title 'Firefox private browsing must be disabled.'
  desc 'Private browsing allows the user to browse the internet without recording their browsing history/activity. From a forensics perspective, this is unacceptable. Best practice requires that browser history is retained.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "DisablePrivateBrowsing" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Private Browsing
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisablePrivateBrowsing</key>
<true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisablePrivateBrowsing": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54998r807159_chk'
  tag severity: 'medium'
  tag gid: 'V-251563'
  tag rid: 'SV-251563r879587_rule'
  tag stig_id: 'FFOX-00-000019'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54952r807160_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
