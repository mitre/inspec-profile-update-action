control 'SV-251562' do
  title 'Firefox must prevent the user from quickly deleting data.'
  desc 'There should not be an option for a user to "forget" work they have done. This is required to meet non-repudiation controls.'
  desc 'check', 'Type "about:policies" in the browser address bar. 

If "DisableForgetButton" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Forget Button
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisableForgetButton</key>
<true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableForgetButton": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54997r807156_chk'
  tag severity: 'medium'
  tag gid: 'V-251562'
  tag rid: 'SV-251562r849961_rule'
  tag stig_id: 'FFOX-00-000018'
  tag gtitle: 'SRG-APP-000326'
  tag fix_id: 'F-54951r807157_fix'
  tag 'documentable'
  tag cci: ['CCI-002355']
  tag nist: ['AC-24 (2)']
end
