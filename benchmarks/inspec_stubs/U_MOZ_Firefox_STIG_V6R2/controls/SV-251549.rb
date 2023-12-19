control 'SV-251549' do
  title 'Firefox must be configured to not automatically update installed add-ons and plugins.'
  desc 'Set this to false to disable checking for updated versions of the Extensions/Themes. Automatic updates from untrusted sites puts the enclave at risk of attack and may override security settings.'
  desc 'check', 'Type "about:policies" in the browser window.

If "ExtensionUpdate" is not displayed under Policy Name or the Policy Value is not "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox\\Extensions
Policy Name: Extension Update
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>ExtensionUpdate</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"ExtensionUpdate": false'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54984r807117_chk'
  tag severity: 'medium'
  tag gid: 'V-251549'
  tag rid: 'SV-251549r807119_rule'
  tag stig_id: 'FFOX-00-000005'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54938r807118_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
