control 'SV-251551' do
  title 'Firefox must be configured to disable form fill assistance.'
  desc 'To protect privacy and sensitive data, Firefox provides the ability to configure the program so that data entered into forms is not saved. This mitigates the risk of a website gleaning private information from prefilled information.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "DisableFormHistory" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Form History
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisableFormHistory</key>
<true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableFormHistory": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54986r807123_chk'
  tag severity: 'medium'
  tag gid: 'V-251551'
  tag rid: 'SV-251551r807125_rule'
  tag stig_id: 'FFOX-00-000007'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54940r807124_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
