control 'SV-251566' do
  title 'Firefox network prediction must be disabled.'
  desc 'If network prediction is enabled, requests to URLs are made without user consent. The browser should always make a direct DNS request without prefetching occurring.'
  desc 'check', 'Type "about:policies" in the browser window. 

If "NetworkPrediction" is not displayed under Policy Name or the Policy Value is not "false", this is a finding.'
  desc 'fix', 'Windows group policy:
1. Open the group policy editor tool with "gpedit.msc".
2. Navigate to Policy Path: Computer Configuration\\Administrative Templates\\Mozilla\\Firefox
Policy Name: Network Prediction
Policy State: Disabled

macOS "plist" file:
Add the following:
<key>NetworkPrediction</key>
<false/>

Linux "policies.json" file:
Add the following in the policies section:
"NetworkPrediction": false'
  impact 0.5
  ref 'DPMS Target Mozilla Firefox 2021 VERSION'
  tag check_id: 'C-55001r807168_chk'
  tag severity: 'medium'
  tag gid: 'V-251566'
  tag rid: 'SV-251566r879587_rule'
  tag stig_id: 'FFOX-00-000022'
  tag gtitle: 'SRG-APP-000141'
  tag fix_id: 'F-54955r807169_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
