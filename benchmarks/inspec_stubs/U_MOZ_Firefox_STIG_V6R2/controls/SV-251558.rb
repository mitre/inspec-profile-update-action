control 'SV-251558' do
  title 'Background submission of information to Mozilla must be disabled.'
  desc 'Firefox by default sends information about Firefox to Mozilla servers. There should be no background submission of technical and other information from DoD computers to Mozilla with portions posted publicly.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "DisableTelemetry" is not displayed under Policy Name or the Policy Value is not "true", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Disable Telemetry
Policy State: Enabled

macOS "plist" file:
Add the following:
<key>DisableTelemetry</key>
<true/>

Linux "policies.json" file:
Add the following in the policies section:
"DisableTelemetry": true'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-54993r807144_chk'
  tag severity: 'medium'
  tag gid: 'V-251558'
  tag rid: 'SV-251558r807146_rule'
  tag stig_id: 'FFOX-00-000014'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54947r807145_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
